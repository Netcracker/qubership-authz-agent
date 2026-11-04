# Fills in the profile fields a realm user needs to log in, keeping any that the
# user already declares. The last name is the username without the "parity-"
# prefix, each part capitalized: parity-r29-level-m2m becomes R29LevelM2M.
# A service account's user, one with serviceAccountClientId, is left as it is:
# the user Keycloak creates for a client has no names or email, and its token
# comes from a client credentials grant, which needs none.
def profile:
  if .serviceAccountClientId then .
  else
    .firstName //= "Parity"
    | .lastName //= (.username | ltrimstr("parity-") | split("-")
        | map(if test("^([a-z][0-9]+|m2m)$") then ascii_upcase
              else (.[:1] | ascii_upcase) + .[1:] end)
        | join(""))
    | .email //= (.username + "@example.test")
  end;
