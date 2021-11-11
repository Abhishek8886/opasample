package app.authz

default allow = false

allow {
  
  input.method == "GET"
  input.path == ["/validus/userInfo"]
  
  
}



