-- =====================================================================
--  חלוקת הזמנות — מבנה Supabase מוצע ל-MVP
--  טבלאות: profiles, couriers, people, clients, tasks, stops
--  העיקרון: השליח לא קורא את people בכלל. הוא רואה רק stops שהוקצו לו,
--  במשימות פעילות, ומעדכן סטטוס רק דרך הפונקציה mark_stop.
-- =====================================================================

-- ---------- משתמשים ותפקידים ----------
create type app_role as enum ('admin', 'courier');

create table profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  role        app_role not null default 'courier',
  full_name   text not null,
  phone       text,
  created_at  timestamptz not null default now()
);

-- שליח = פרופיל עם role='courier'. טבלה נפרדת לנתונים תפעוליים (צבע, פעיל)
create table couriers (
  id          uuid primary key references profiles(id) on delete cascade,
  color       text not null default '#2F6FDB',
  active      boolean not null default true
);

create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$$;

-- ---------- מאגר אנשים (פרטי, למנהל בלבד) ----------
create table people (
  id          uuid primary key default gen_random_uuid(),
  first_name  text not null,
  last_name   text not null,
  phone       text,
  area        text,
  address     text,
  lat         double precision,
  lng         double precision,
  notes       text,                           -- תיאור הבית, מוצג לשליח דרך העותק שב-stops
  name_key    text generated always as (lower(first_name || ' ' || last_name)) stored,
  created_at  timestamptz not null default now()
);
create index people_name_key_idx on people (name_key);
-- להתאמה עמומה (שמות דומים): create extension pg_trgm; + אינדקס gin על name_key

-- ---------- לקוחות ומשימות (מוכן לריבוי לקוחות ואירועים במקביל) ----------
create table clients (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  phone       text,
  created_at  timestamptz not null default now()
);

create type task_status as enum ('draft', 'active', 'done');

create table tasks (
  id            uuid primary key default gen_random_uuid(),
  number        serial unique,                -- מספר משימה שמוצג לשליח
  client_id     uuid references clients(id),  -- אופציונלי ב-MVP
  event_name    text not null,
  distribution_date date not null,
  expected_count int,
  status        task_status not null default 'draft',
  created_at    timestamptz not null default now(),
  activated_at  timestamptz,
  closed_at     timestamptz
);

-- ---------- עצירות: מוזמן אחד במשימה ----------
create type match_state  as enum ('matched', 'ambiguous', 'unmatched');
create type stop_status  as enum ('pending', 'delivered', 'retry', 'failed');
create type fail_reason  as enum ('not_home', 'bad_addr', 'return', 'other');

create table stops (
  id            uuid primary key default gen_random_uuid(),
  task_id       uuid not null references tasks(id) on delete cascade,
  seq           int not null,                 -- הסדר ברשימה של הלקוח
  -- מה שהלקוח מסר
  first_name    text not null,
  last_name     text not null,
  phone         text,
  list_area     text,
  list_address  text,
  -- התאמה למאגר
  person_id     uuid references people(id) on delete set null,
  match         match_state not null default 'unmatched',
  candidates    uuid[] not null default '{}',
  -- עותק של המיקום בזמן השיוך: זה כל מה שהשליח צריך
  area          text,
  address       text,
  description   text,
  lat           double precision,
  lng           double precision,
  -- שיוך ומסירה
  courier_id    uuid references couriers(id),
  route         int,                          -- הסדר במסלול של השליח
  status        stop_status not null default 'pending',
  reason        fail_reason,
  note          text,
  updated_at    timestamptz,
  delivered_at  timestamptz
);
create index stops_task_idx    on stops (task_id);
create index stops_courier_idx on stops (courier_id, status);

-- ---------- RLS ----------
alter table profiles enable row level security;
alter table couriers enable row level security;
alter table people   enable row level security;
alter table clients  enable row level security;
alter table tasks    enable row level security;
alter table stops    enable row level security;

-- מנהל: הכל
create policy admin_all_profiles on profiles for all using (is_admin()) with check (is_admin());
create policy admin_all_couriers on couriers for all using (is_admin()) with check (is_admin());
create policy admin_all_people   on people   for all using (is_admin()) with check (is_admin());
create policy admin_all_clients  on clients  for all using (is_admin()) with check (is_admin());
create policy admin_all_tasks    on tasks    for all using (is_admin()) with check (is_admin());
create policy admin_all_stops    on stops    for all using (is_admin()) with check (is_admin());

-- שליח: הפרופיל של עצמו
create policy courier_self on profiles for select using (id = auth.uid());

-- פונקציות עזר (security definer) כדי שה-policies של tasks ו-stops לא יפנו זו לזו בלולאה
create or replace function task_is_active(p_task uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from tasks where id = p_task and status = 'active');
$$;
create or replace function courier_in_task(p_task uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from stops where task_id = p_task and courier_id = auth.uid());
$$;

-- שליח: רק משימות פעילות שיש לו בהן עצירות
create policy courier_tasks on tasks for select using (status = 'active' and courier_in_task(id));

-- שליח: רק העצירות שלו במשימות פעילות. אין לו שום policy על people.
create policy courier_stops on stops for select using (courier_id = auth.uid() and task_is_active(task_id));

-- השליח לא מקבל UPDATE ישיר על stops (כדי שלא ישנה כתובת או שיוך).
-- עדכון סטטוס רק דרך הפונקציה הזו:
create or replace function mark_stop(p_stop uuid, p_status stop_status, p_reason fail_reason default null, p_note text default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  update stops s
     set status = p_status,
         reason = case when p_status in ('retry','failed') then p_reason else null end,
         note = coalesce(p_note, ''),
         updated_at = now(),
         delivered_at = case when p_status = 'delivered' then now() else null end
   where s.id = p_stop
     and s.courier_id = auth.uid()
     and exists (select 1 from tasks t where t.id = s.task_id and t.status = 'active');
  if not found then raise exception 'stop not assigned to you'; end if;
end $$;
revoke all on function mark_stop from public;
grant execute on function mark_stop to authenticated;

-- ---------- Realtime: המנהל רואה עדכונים מיד ----------
alter publication supabase_realtime add table stops, tasks;
