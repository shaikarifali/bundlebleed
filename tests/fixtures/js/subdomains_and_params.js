// Synthetic fixture with internal subdomains and security-interesting variable names.
var config = {
  api: "https://internal-api.example.com/v1",
  admin: "https://admin.example.com/panel",
  cdn: "https://cdn.unrelated-domain.com/assets",
};

const userId = getCurrentUserId();
const redirectUrl = window.location.href;
const authToken = getAuthToken();
const isAdmin = checkAdmin();
const greeting = "hello";
