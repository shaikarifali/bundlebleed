// Synthetic fixture: a source (location.hash) flowing toward a sink (innerHTML).
function render() {
  var frag = location.hash.substring(1);
  document.getElementById("widget").innerHTML = frag;
}
