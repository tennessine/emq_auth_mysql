%%--------------------------------------------------------------------
%% Copyright (c) 2012-2016 Feng Lee <feng@emqtt.io>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_mysql).

-behaviour(emqttd_auth_mod).

-include_lib("emqttd/include/emqttd.hrl").

-include("emq_auth_mysql.hrl").

-import(emq_auth_mysql_cli, [is_superuser/2, query/3, insert/3, parse_query/1]).

-export([init/1, check/3, description/0]).
-export([load/1, unload/0]).

%% Hooks functions
-export([on_client_connected/3, on_client_disconnected/3, on_message_publish/2]).

-record(state, {auth_query, super_query, hash_type}).

-define(EMPTY(Username), (Username =:= undefined orelse Username =:= <<>>)).

%% TODO
load(Env) ->
    emqttd:hook('client.connected', fun ?MODULE:on_client_connected/3, [Env]),
    emqttd:hook('client.disconnected', fun ?MODULE:on_client_disconnected/3, [Env]),
    emqttd:hook('message.publish', fun ?MODULE:on_message_publish/2, [Env]).

on_client_connected(_ConnAck, Client, _Env) ->
    UpdateStatusOnline = parse_query(application:get_env(?APP, update_status_online, undefined)),
    {Sql, Params} = UpdateStatusOnline,
    query(Sql, Params, Client),
    {ok, Client}.

on_client_disconnected(_Reason, Client, _Env) ->
    UpdateStatusOffline = parse_query(application:get_env(?APP, update_status_offline, undefined)),
    {Sql, Params} = UpdateStatusOffline,
    query(Sql, Params, Client),
    ok.

on_message_publish(Message = #mqtt_message{topic = <<"$SYS/", _/binary>>}, _Env) ->
    {ok, Message};

on_message_publish(Message, _Env) ->
    InsertQuery = parse_query(application:get_env(?APP, insert_query, undefined)),
    {Sql, Params} = InsertQuery,
    insert(Sql, Params, Message),
    {ok, Message}.

unload() ->
    emqttd:unhook('client.connected', fun ?MODULE:on_client_connected/3),
    emqttd:unhook('client.disconnected', fun ?MODULE:on_client_disconnected/3),
    emqttd:unhook('message.publish', fun ?MODULE:on_message_publish/2).
%% TODO

init({AuthQuery, SuperQuery, HashType}) ->
    {ok, #state{auth_query = AuthQuery, super_query = SuperQuery, hash_type = HashType}}.

check(#mqtt_client{username = Username}, Password, _State) when ?EMPTY(Username); ?EMPTY(Password) ->
    {error, username_or_password_undefined};

check(Client, Password, #state{auth_query  = {AuthSql, AuthParams},
                               super_query = SuperQuery,
                               hash_type   = HashType}) ->
    Result = case query(AuthSql, AuthParams, Client) of
                 {ok, [<<"password">>], [[PassHash]]} ->
                     check_pass(PassHash, Password, HashType);
                 {ok, [<<"password">>, <<"salt">>], [[PassHash, Salt]]} ->
                     check_pass(PassHash, Salt, Password, HashType);
                 {ok, _Columns, []} ->
                     {error, notfound};
                 {error, Reason} ->
                     {error, Reason}
             end,
    case Result of ok -> {ok, is_superuser(SuperQuery, Client)}; Error -> Error end.

check_pass(PassHash, Password, HashType) ->
    check_pass(PassHash, hash(HashType, Password)).
check_pass(PassHash, Salt, Password, {salt, HashType}) ->
    check_pass(PassHash, hash(HashType, <<Salt/binary, Password/binary>>));
check_pass(PassHash, Salt, Password, {HashType, salt}) ->
    check_pass(PassHash, hash(HashType, <<Password/binary, Salt/binary>>)).

check_pass(PassHash, PassHash) -> ok;
check_pass(_, _)               -> {error, password_error}.

description() -> "Authentication with MySQL".

hash(Type, Password) -> emqttd_auth_mod:passwd_hash(Type, Password).

