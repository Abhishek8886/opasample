package app.authz

default allow = false


allow {
  input.method == "GET"
  input.path == ["/validus/userInfo",username]
  
}


allow {
  input.method == "GET"
  input.path = "bye"
  
}
 

# user is allowed if he has a user role
is_user {

	# for some `i`...
	some i

  input.roles[i] == "ROLE_USER"
}

# user is allowed if he has a admin role
is_admin {

	# for some `i`...
	some i

  input.roles[i] == "ROLE_ADMIN"
}
