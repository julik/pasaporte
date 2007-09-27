function cboxToggle(checkBox, depItem) {
  if (checkBox.checked) { document.getElementById(depItem).style.display = "block";
  } else { document.getElementById(depItem).style.display = "none"; }
}

function attachCheckbox(cBox, depItem) {
  var cbox = document.getElementById(cBox);
  cbox.onchange = function(the) { cboxToggle((the.target || the.srcElement), depItem); }
  cboxToggle(cbox, depItem);
}