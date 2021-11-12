package app.authz

default allow = false

user_roles := {
    "krishna":["ak1","ak2"],
    "sumit":["ak14"]
}


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
  user_roles[input.userid][_] == profile_id

}

allow {
  some profile_id
  input.method == "GET"
  input.path = ["validus","userInfo", profile_id]
  input.roles[_] == "Admin"
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
  input.roles[_] == "Admin"
}

allow {
  input.method == "GET"
  input.path = ["validus","userInfo", "all"]
  input.roles[_] == "Admin"
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
  input.roles[_] == "Admin"
}

allow {
  some profile_id
  input.method == "GET"
  input.path = ["validus","group","user", profile_id]
  profile_id == input.user_id
}

allow {
  some group_id
  input.method == "GET"
  input.path = ["validus","group", group_id]
  input.roles[_]  ==  group_id
}



allow {
  some group_id
  input.method == "GET"
  input.path = ["validus","group", group_id]
  input.roles[_] == "Admin"
}


allow {
  
  input.method == "POST"
  input.path = ["validus","group", "addUser"]
  input.roles[_] == "Admin"
}

allow {
  
  input.method == "POST"
  input.path = ["validus","group", "removerUser"]
  input.roles[_] == "Admin"
}








