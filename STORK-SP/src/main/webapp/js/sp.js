
function initCustomCombos() {
    try {
        var speps = $("#speps").msDropdown().data("dd");
        speps.on("change", showUrl);

        $("#citizen").msDropdown();

        var spepseidas = $("#spepseidas").msDropdown().data("dd");
        spepseidas.on("change", showEidasUrl);

        $("#citizeneidas").msDropdown();

        var speps2 = $("#speps2").msDropdown().data("dd");
        speps2.on("change", showUrl2);
    } catch (e) {
        //console.debug(e);
        alert(e);
    }
}

function initTabs() {
    var tabContainers = $('div.tabs > div');

    $('div.tabs ul.tabNavigation a').click(function () {
        tabContainers.hide().filter(this.hash).show();

        $('div.tabs ul.tabNavigation a').removeClass('selected');
        $(this).addClass('selected');

        return false;
    }).filter(function(index) {
		if(index==1){ //eidas by default
			return true;
		}
	}).click();
}

function initPlugin() {

}

function checkAll(type) {
    $("[id^="+type+"_]").each(function (index, el) {
        el.checked = true;
    });
}

window.addEventListener('load', initCustomCombos());
window.addEventListener('load', initTabs());
window.addEventListener('load', initPlugin());

document.getElementById("speps").addEventListener("change", showUrl);
document.getElementById("spepseidas").addEventListener("change", showEidasUrl);

document.getElementById("speps2").addEventListener("change", showUrl2);

/** onclick events listeners to check all radio buttons **/
document.getElementById("check_all_Mandatory").addEventListener("click", function() {
    checkAll("Mandatory");
});
document.getElementById("check_all_Optional").addEventListener("click",  function() {
    checkAll("Optional");
});
document.getElementById("check_all_NoRequest").addEventListener("click",  function() {
    checkAll("NoRequest");
});

document.getElementById("check_all_MandatoryEidas").addEventListener("click", function() {
    checkAll("Mandatory");
});
document.getElementById("check_all_OptionalEidas").addEventListener("click",  function() {
    checkAll("Optional");
});
document.getElementById("check_all_NoRequestEidas").addEventListener("click",  function() {
    checkAll("NoRequest");
});

document.getElementById("check_all_Mandatory2").addEventListener("click", function() {
    checkAll("2Mandatory");
});
document.getElementById("check_all_Optional2").addEventListener("click", function() {
    checkAll("2Optional");
});
document.getElementById("check_all_NoRequest2").addEventListener("click", function() {
    checkAll("2NoRequest");
});
