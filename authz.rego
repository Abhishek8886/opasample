package app.authz

default allow = false

allow {
  some profile_id
  input.method == "GET"
  input.path == ["/validus/userInfo",profile_id]
  profile_id == input.user_id
}



