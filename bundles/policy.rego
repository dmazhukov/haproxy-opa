package authz
import future.keywords.in



default allow = false



#allowed_groups_app1 = ["group1"]
#allowed_groups_app2 = ["group2"]



allowed_users_app1 = ["user1@tkqlm.onmicrosoft.com"]
allowed_users_app2 = ["user2@tkqlm.onmicrosoft.com"]



allow {
# Allow access to groups and specific email for app1
input.appid == "app1"
input.groups[_] == "f55e7826-883e-48d2-842e-65c7d02e8ad1"
input.email in allowed_users_app1
token.payload.user == input.email
user_owns_token
}



allow {
# Allow access to all members of dev group and specific email for app2
input.appid == "app2"
input.groups[_] == "40c4717b-76b6-4dfa-8a09-c4abb628837b"
input.email in allowed_users_app2

}

user_owns_token { input.email == token.payload.azp }

token := {"payload": payload} {
    [header, payload, signature] := io.jwt.decode(input.token)
}

# package httpapi.authz

# # bob is alice's manager, and betty is charlie's.
# subordinates := {"alice": [], "charlie": [], "bob": ["alice"], "betty": ["charlie"]}

# default allow := false

# # Allow users to get their own salaries.
# allow {
#     input.method == "GET"
#     input.path == ["finance", "salary", input.user]
# }

# # Allow managers to get their subordinates' salaries.
# allow {
#     some username
#     input.method == "GET"
#     input.path = ["finance", "salary", username]
#     subordinates[input.user][_] == username
# }