var drop = document.getElementById("drp-cat")
drop.addEventListener('click',function (e) {
    document.getElementById("drpdwnList").classList.toggle("show");
}
  ) 

var dropplace = document.getElementById("drp-places")
dropplace.addEventListener('click',function (e) {
    document.getElementById("drpdwnListplaces").classList.toggle("show");
}
  ) 


window.onclick = function(event) {
  if (!event.target.matches('.drpbtn-cat')) {

    var dropdowns = document.getElementsByClassName("cat-List");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
      var openDropdown = dropdowns[i];
      if (openDropdown.classList.contains('show')) {
        openDropdown.classList.remove('show');
      }
    }
  }

 if (!event.target.matches('.drpbtn-places')) {

    var dropdowns = document.getElementsByClassName("place-List");
    var i;
    for (i = 0; i < dropdowns.length; i++) {
      var openDropdown = dropdowns[i];
      if (openDropdown.classList.contains('show')) {
        openDropdown.classList.remove('show');
      }
    }
  }
}


