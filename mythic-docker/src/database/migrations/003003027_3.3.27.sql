-- +migrate Up

alter table public.consuming_container
    add column crypto_capabilities jsonb not null default '{}'::jsonb;

alter table public.payloadtype
    add column supported_crypto_schemes jsonb not null default '[]'::jsonb
    check (jsonb_typeof(supported_crypto_schemes) = 'array'
        and jsonb_array_length(supported_crypto_schemes) <= 128);

create table public.crypto_provider_state (
    provider_id integer not null references public.consuming_container(id),
    namespace text not null,
    state_id text not null,
    state_blob bytea not null,
    provider_json jsonb not null default '{}'::jsonb,
    revision bigint not null default 0 check (revision >= 0),
    owner_epoch bigint not null default 0 check (owner_epoch >= 0),
    updated_at timestamptz not null default now(),
    primary key (provider_id, namespace, state_id)
);

create table public.crypto_provider_result (
    provider_id integer not null,
    namespace text not null,
    state_id text not null,
    request_id text not null,
    input_digest text not null check (input_digest ~ '^[0-9a-f]{64}$'),
    result jsonb not null,
    revision bigint not null check (revision >= 0),
    created_at timestamptz not null default now(),
    primary key (provider_id, namespace, state_id, request_id),
    foreign key (provider_id, namespace, state_id)
        references public.crypto_provider_state(provider_id, namespace, state_id)
);

create table public.crypto_provider_binding (
    id uuid primary key,
    profile_id uuid references public.crypto_provider_binding(id),
    provider_id integer not null references public.consuming_container(id),
    operation_id integer not null references public.operation(id),
    scheme text not null,
    profile_ref text not null default '',
    session_ref text not null default '',
    namespace text not null default '',
    state_id text not null default '',
    provider_json jsonb not null default '{}'::jsonb,
    agent_config bytea,
    enc_key bytea,
    dec_key bytea,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index crypto_provider_session_identity
    on public.crypto_provider_binding(provider_id, operation_id, namespace, state_id, session_ref)
    where session_ref <> '';

create table public.crypto_provider_exchange (
    binding_id uuid not null references public.crypto_provider_binding(id),
    route_uuid uuid not null,
    input_digest text not null check (input_digest ~ '^[0-9a-f]{64}$'),
    request_id uuid not null unique,
    next_uuid uuid not null,
    dispatch_response bytea,
    seal_input bytea,
    response bytea,
    created_at timestamptz not null default now(),
    session_binding_id uuid references public.crypto_provider_binding(id),
    primary key (binding_id, route_uuid, input_digest)
);

create index crypto_provider_exchange_route_input
    on public.crypto_provider_exchange(route_uuid, input_digest);

create index crypto_provider_exchange_pending
    on public.crypto_provider_exchange(binding_id, route_uuid)
    where response is null;

alter table public.buildparameterinstance
    add column crypto_provider_binding_id uuid references public.crypto_provider_binding(id);
alter table public.c2profileparametersinstance
    add column crypto_provider_binding_id uuid references public.crypto_provider_binding(id);
alter table public.staginginfo
    add column crypto_provider_binding_id uuid references public.crypto_provider_binding(id);
alter table public.callback
    add column crypto_provider_binding_id uuid references public.crypto_provider_binding(id);

create unique index callback_crypto_provider_binding_unique
    on public.callback(crypto_provider_binding_id)
    where crypto_provider_binding_id is not null;
create index staginginfo_crypto_provider_binding
    on public.staginginfo(crypto_provider_binding_id)
    where crypto_provider_binding_id is not null;

-- +migrate Down

drop index public.staginginfo_crypto_provider_binding;
drop index public.callback_crypto_provider_binding_unique;
alter table public.callback drop column crypto_provider_binding_id;
alter table public.staginginfo drop column crypto_provider_binding_id;
alter table public.c2profileparametersinstance drop column crypto_provider_binding_id;
alter table public.buildparameterinstance drop column crypto_provider_binding_id;
drop table public.crypto_provider_exchange;
drop table public.crypto_provider_binding;
drop table public.crypto_provider_result;
drop table public.crypto_provider_state;
alter table public.payloadtype drop column supported_crypto_schemes;
alter table public.consuming_container drop column crypto_capabilities;
