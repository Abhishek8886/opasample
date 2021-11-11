package http.authz

default allow = false

allow {
  some username
  input.method == "GET"
  input.path == ["/validus/userInfo",username]
  username == input.username
  
}



