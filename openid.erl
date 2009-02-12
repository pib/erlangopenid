%%%-------------------------------------------------------------------
%%% File : openid.erl
%%% Author : Paul Bonser <pib@paulbonser.com>
%%% Description : Implement the OpenId 1.1 "dumb mode" consumer protocol
%%%
%%% Created : 20 Jan 2009 by Paul Bonser <pib@paulbonser.com>
%%%-------------------------------------------------------------------
-module(openid).

-export([start_authentication/2, finish_authentication/1]).
-export([discover/1, checkid_setup_url/2, checkid_setup_url/3, check_authentication/2]).

start_authentication(Identifier, ReturnTo) ->
	DiscoResponse = discover(Identifier),
	checkid_setup_url(DiscoResponse, ReturnTo).

finish_authentication(Params) ->
	Server = proplists:get_value("identity_provider", Params),
	case proplists:get_value("openid.mode", Params) of
        "id_res" ->
            case check_authentication(Server, Params) of
                true ->
                    {ok, proplists:get_value("original_identifier", Params)};
                false -> {error, bad_auth};
                Error -> {error, Error}
            end;
        "cancel" ->
            {error, cancelled};
        "error" ->
            {error, proplists:get_value("openid.error", Params)}
    end.

check_authentication(Server, Params) ->
	Params2 = proplists:delete("openid.mode", Params),

	case http:request(post, {
                        Server,
                        [],
                        "application/x-www-form-urlencoded",
                        mochiweb_util:urlencode(
                          [{"openid.mode", "check_authentication"} | Params2])},
                      [],
                      []) of
        {ok, {_Status, _Headers, Body}} ->
            Response = parse_key_value(Body),
            case proplists:get_value("is_valid", Response) of
                "true" -> true;
                _ -> false
            end;
        Error -> Error
	end.

parse_key_value(KeyValueString) ->
	lists:map(fun(Line) -> list_to_tuple(string:tokens(Line, ":")) end,
              string:tokens(KeyValueString, "\n")).

checkid_setup_url(Params, ReturnTo) ->
	checkid_setup_url(Params, ReturnTo, ReturnTo).

checkid_setup_url(Params, ReturnTo, TrustRoot) ->
	Server = proplists:get_value(server, Params),
	Identifier = proplists:get_value(identifier, Params),
	Delegate = proplists:get_value(delegate, Params, Identifier),

	Server ++ "?" ++ mochiweb_util:urlencode(
                       [
                        {"openid.mode", "checkid_setup"},
                        {"openid.identity", Delegate},
                        {"openid.return_to", ReturnTo ++ "?" ++
                         mochiweb_util:urlencode(
                           [
                            {"original_identifier", Identifier},
                            {"identity_provider", Server}
                           ])},
                        {"openid.trust_root", TrustRoot}
                       ]).

discover(Identifier) ->
	NormalizedIdentifier = normalize_identifier(Identifier),
	case http:request(NormalizedIdentifier) of
        {ok, {_Status, _Headers, Body}} ->
            HtmlTokens = mochiweb_html:parse(Body),
            [{identifier, NormalizedIdentifier} | find_openid_tags(HtmlTokens)];
        _ ->
            {error, http_error}
	end.

normalize_identifier(Ident = "http://" ++ _Rest) ->
	Ident;
normalize_identifier(Ident) ->
	"http://" ++ Ident.

find_openid_tags(HtmlTokens) ->
	case find_tag(<<"head">>, [HtmlTokens]) of
        {<<"head">>, _Attrs, Children, _Rest} ->
            case find_tag_with_attr(<<"link">>, {<<"rel">>, <<"openid.server">>}, Children) of
                not_found ->
                    {error, openid_server_not_found};
                ServerAttrs ->
                    Server = proplists:get_value(<<"href">>, ServerAttrs),
                    case find_tag_with_attr(<<"link">>, {<<"rel">>, <<"openid.delegate">>}, Children) of
                        not_found ->
                            [{server, Server}];
                        DelegateAttrs ->
                            Delegate = proplists:get_value(<<"href">>, DelegateAttrs),
                            [{server, binary_to_list(Server)},
                             {delegate, binary_to_list(Delegate)}]
                    end
            end;
        not_found ->
            {error, no_head_tag}
 	end.

find_tag(_TagName, []) ->
 	not_found;
find_tag(TagName, [{TagName, Attributes, Children} | Rest]) ->
 	{TagName, Attributes, Children, Rest};
find_tag(TagName, [{_OtherTag, _Attributes, Children} | Rest]) ->
 	find_tag(TagName, Children ++ Rest);
find_tag(TagName, [_Other | Rest]) ->
 	find_tag(TagName, Rest).

find_tag_with_attr(_TagName, {_AttrKey, _AttrVal}, []) ->
 	not_found;
find_tag_with_attr(TagName, Attr = {AttrKey, AttrVal}, Tags) ->
 	case find_tag(TagName, Tags) of
        not_found ->
            not_found;
        {TagName, Attributes, Children, Rest} ->
            case proplists:get_value(AttrKey, Attributes) of
                AttrVal ->
                    Attributes;
                _ ->
                    find_tag_with_attr(TagName, Attr, Children ++ Rest)
            end
 	end. 
