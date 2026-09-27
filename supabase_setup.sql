-- =====================================================================
--  חלוקת הזמנות — הקמת Supabase לסנכרון בין מחשב לטלפון
--  הרצה: Supabase → SQL Editor → New query → הדבק הכל → Run
--  לפני ההרצה: החלף את כתובת האימייל בשורה האחרונה באימייל שלך.
-- =====================================================================

-- מי מורשה לגשת לנתונים (רק משתמשים שהאימייל שלהם ברשימה)
create table if not exists allowed_users (email text primary key);
alter table allowed_users enable row level security;

create or replace function is_allowed() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from allowed_users where lower(email) = lower(auth.jwt() ->> 'email'));
$$;

-- טבלה לכל אוסף: מזהה + מסמך JSON (אותו מבנה נתונים שהאפליקציה כבר עובדת איתו)
do $$
declare t text;
begin
  foreach t in array array['couriers', 'people', 'tasks', 'stops'] loop
    execute format('create table if not exists %I (id text primary key, data jsonb not null default ''{}''::jsonb, updated_at timestamptz not null default now())', t);
    execute format('alter table %I enable row level security', t);
    execute format('drop policy if exists team_all on %I', t);
    execute format('create policy team_all on %I for all to authenticated using (is_allowed()) with check (is_allowed())', t);
    execute format('alter table %I replica identity full', t);
  end loop;
end $$;

-- אינדקסים לסינון נפוץ
create index if not exists stops_courier_idx on stops ((data ->> 'courierId'));
create index if not exists stops_task_idx on stops ((data ->> 'taskId'));

-- עדכון חלקי של מסמך (מיזוג שדות) — רץ עם הרשאות המשתמש המחובר, כך שה-RLS חל עליו
create or replace function merge_doc(t text, doc_id text, patch jsonb) returns void
language plpgsql security invoker set search_path = public as $$
begin
  if t not in ('couriers', 'people', 'tasks', 'stops') then raise exception 'unknown table %', t; end if;
  execute format('update %I set data = data || $1, updated_at = now() where id = $2', t) using patch, doc_id;
  if not found then raise exception 'document % not found in %', doc_id, t; end if;
end $$;
revoke all on function merge_doc(text, text, jsonb) from public, anon;
grant execute on function merge_doc(text, text, jsonb) to authenticated;

-- עדכונים בזמן אמת (מה שנשמר בטלפון מופיע במחשב מיד)
do $$
declare t text;
begin
  foreach t in array array['couriers', 'people', 'tasks', 'stops'] loop
    begin
      execute format('alter publication supabase_realtime add table %I', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;

-- ↓↓↓ החלף באימייל שלך (אותו אימייל שתיצור לו משתמש ב-Authentication → Users)
insert into allowed_users (email) values ('YOUR_EMAIL@example.com') on conflict do nothing;
