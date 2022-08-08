exports.parse = function (json) {
  if (typeof json === "string") {
    json = JSON.parse(json);
  }

  var profile = {
    id: String(json.user_id),
    username: json.user_name,
    given_name: json.given_name,
    family_name: json.family_name,
    name: json.name,
    email: json.email,
  };

  return profile;
};
