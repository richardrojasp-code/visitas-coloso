-- Visitas en terreno - Puerto Coloso
-- Esquema de base de datos para Supabase. Ejecutar completo en: SQL Editor > New query > Run.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.visitas (
  id uuid primary key default gen_random_uuid(),
  creado timestamptz not null default now(),
  actualizado timestamptz not null default now(),
  fecha date not null,
  turno text,
  etapa text,
  supervisor text not null,
  evaluador text,
  tarea text,
  procedimiento text,
  is_list text[] not null default '{}',
  obs jsonb,
  obs_nota jsonb,
  aud jsonb,
  evid jsonb,
  brecha text,
  accion_resp text,
  accion_fecha date,
  accion_estado text not null default 'abierta' check (accion_estado in ('abierta','cerrada')),
  p_tec numeric,
  p_seg numeric,
  p_tot numeric,
  p_ubica numeric
);

-- Seguridad: cualquiera con el link puede ver y registrar visitas; solo el administrador edita, cierra acciones y elimina.
alter table public.visitas enable row level security;
drop policy if exists "leer visitas" on public.visitas;
create policy "leer visitas" on public.visitas for select to anon, authenticated using (true);
drop policy if exists "registrar visitas" on public.visitas;
create policy "registrar visitas" on public.visitas for insert to anon, authenticated
  with check (length(coalesce(supervisor,'')) between 1 and 120 and accion_estado = 'abierta');

-- Clave de administrador (se guarda cifrada; nadie puede leer esta tabla desde la app)
create table if not exists public.admin_config (
  id int primary key default 1 check (id = 1),
  clave_hash text not null
);
alter table public.admin_config enable row level security;
revoke all on public.admin_config from anon, authenticated;

create or replace function public.admin_verificar(p_clave text)
returns boolean language sql security definer set search_path = public, extensions as $$
  select coalesce((select clave_hash = extensions.crypt(p_clave, clave_hash) from public.admin_config where id = 1), false);
$$;

create or replace function public.admin_estado_accion(p_clave text, p_id uuid, p_estado text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.admin_verificar(p_clave) then raise exception 'Clave de administrador incorrecta'; end if;
  update public.visitas set accion_estado = p_estado, actualizado = now() where id = p_id;
end $$;

create or replace function public.admin_eliminar(p_clave text, p_id uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.admin_verificar(p_clave) then raise exception 'Clave de administrador incorrecta'; end if;
  delete from public.visitas where id = p_id;
end $$;

create or replace function public.admin_actualizar(p_clave text, p_id uuid, p_data jsonb)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.admin_verificar(p_clave) then raise exception 'Clave de administrador incorrecta'; end if;
  update public.visitas set
    fecha = (p_data->>'fecha')::date, turno = p_data->>'turno', etapa = p_data->>'etapa', supervisor = p_data->>'supervisor',
    evaluador = p_data->>'evaluador', tarea = p_data->>'tarea', procedimiento = p_data->>'procedimiento',
    is_list = coalesce(array(select jsonb_array_elements_text(p_data->'is_list')), '{}'),
    obs = p_data->'obs', obs_nota = p_data->'obs_nota', aud = p_data->'aud', evid = p_data->'evid', brecha = p_data->>'brecha',
    accion_resp = p_data->>'accion_resp', accion_fecha = nullif(p_data->>'accion_fecha','')::date,
    accion_estado = coalesce(p_data->>'accion_estado','abierta'),
    p_tec = (p_data->>'p_tec')::numeric, p_seg = (p_data->>'p_seg')::numeric, p_tot = (p_data->>'p_tot')::numeric, p_ubica = (p_data->>'p_ubica')::numeric,
    actualizado = now()
  where id = p_id;
end $$;

revoke all on function public.admin_verificar(text) from public;
revoke all on function public.admin_estado_accion(text, uuid, text) from public;
revoke all on function public.admin_eliminar(text, uuid) from public;
revoke all on function public.admin_actualizar(text, uuid, jsonb) from public;
grant execute on function public.admin_verificar(text) to anon, authenticated;
grant execute on function public.admin_estado_accion(text, uuid, text) to anon, authenticated;
grant execute on function public.admin_eliminar(text, uuid) to anon, authenticated;
grant execute on function public.admin_actualizar(text, uuid, jsonb) to anon, authenticated;

-- Actualización en vivo de los resultados
do $$ begin
  alter publication supabase_realtime add table public.visitas;
exception when others then null; end $$;

-- ============================================================
-- PASO FINAL (lo ejecuta Richard, en una consulta aparte):
-- reemplace ESCRIBA_SU_CLAVE por la clave de administrador que quiera usar.
--
-- insert into public.admin_config (id, clave_hash)
-- values (1, extensions.crypt('ESCRIBA_SU_CLAVE', extensions.gen_salt('bf')))
-- on conflict (id) do update set clave_hash = excluded.clave_hash;
-- ============================================================
