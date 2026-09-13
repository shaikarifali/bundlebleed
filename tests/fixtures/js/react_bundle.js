// Recorded (synthetic, for testing) sample resembling a minified React bundle.
function e(t) {
  return fetch("/api/v1/users/" + t + "/profile").then(function (r) {
    return r.json();
  });
}
function n() {
  return axios.get("/api/v2/orders/{id}");
}
var AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
var STRIPE_KEY = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX";
var config = { url: "https://internal-api.example.com/v1/export" };
$.ajax({ url: "/api/v1/reset", method: "POST" });
var routes = [{ path: "/dashboard/:userId", component: "Dashboard" }];
