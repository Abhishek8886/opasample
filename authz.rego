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
  input.roles[_] == "ADMIN"
}

allow {
  some profile_id
  input.method == "POST"
  input.path = ["validus","userInfo", profile_id]
  profile_id == input.user_id
}

allow {
  some profile_id
  input.method == "POST"
  input.path = ["validus","userInfo", profile_id]
  input.roles[_] == "ADMIN"
}

allow {
  input.method == "GET"
  input.path = ["validus","userInfo", "all"]
  input.roles[_] == "ADMIN"
}

allow {
  some profile_id
  input.method == "GET"
  input.path = ["validus","group","user", profile_id]
  profile_id == input.user_id
  
}

allow {
  some profile_id
  input.method == "GET"
  input.path = ["validus","group","user", profile_id]
  input.roles[_] == "ADMIN"
}


allow {
  some group_id
  input.method == "GET"
  input.path = ["validus","group", group_id]
  input.roles[_] == "ADMIN"
}


allow {
  
  input.method == "POST"
  input.path = ["validus","group", "addUser"]
  input.roles[_] == "ADMIN"
}

allow {
  
  input.method == "POST"
  input.path = ["validus","group", "removerUser"]
  input.roles[_] == "ADMIN"
}








