package app.authz

default allow = false

allow {
  input.method == "POST"
  input.path = ["validus","login"]
}

allow {
  some profile_id
  input.method == "GET"
  input.path = ["validus","userInfo", profile_id]
  profile_id == input.user_id
}

allow {
  some profile_id
  input.method == "GET"
  input.path = ["validus","userInfo", profile_id]
  input.role[_] == "ADMIN
}



