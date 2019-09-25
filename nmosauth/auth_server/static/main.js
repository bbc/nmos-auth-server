/* Copyright 2019 British Broadcasting Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

function errorMessage (XMLHttpRequest, textStatus, errorThrown) {
    console.log(XMLHttpRequest.status + " " + XMLHttpRequest.responseText);
    alert('Error: ' + XMLHttpRequest.status + '\n' + XMLHttpRequest.responseText);
    return false;
}

$(function getToken() {
  var port = window.location.port;
  var host = window.location.hostname;
  $("#token").click(function(){
    username = document.getElementById("username").value
    password = document.getElementById("password").value
    scope = document.getElementById("scope").value
    var requestPayload = {
      'grant_type': 'password',
      'username': username.trim(),
      'password': password,
      'scope': scope.trim()
    };
    if (username == "" || password == "" || scope == "") {
      alert('Error: Please complete all fields');
      return false;
    }
    if (requestPayload.scope.split(" ").length > 1) {
      alert('Error: Please only enter a single scope');
      return false;
    }
    var client_id = document.getElementById("client_id").value;
    var client_secret = document.getElementById("client_secret").value;
    $.ajax({
      url: '//' + host + ':' + port + '/x-nmos/auth/v1.0/token',
      type: 'POST',
      data: requestPayload,
      crossDomain: true,
      beforeSend: function (xhr) {
        xhr.setRequestHeader ("Authorization", "Basic " + btoa(client_id + ":" + client_secret));
      },
      //contentType: 'x-www-form-urlencoded',
      //dataType: 'json'
      success: function(data) {
        var accessToken = data.access_token;
        sessionStorage.setItem('token', accessToken);
        alert('Success!\nAccess Token:\n' + accessToken);
        return data;
      },
      error: errorMessage
    });
  });
});


$(function getResource() {
  $("#resource").click(function(){
    var port = window.location.port;
    var host = window.location.hostname;
    console.log(sessionStorage.getItem('token'));
    $.ajax({
      url: '//' + host + ':' + port + '/x-nmos/auth/v1.0/test/',
      type: 'GET',
      contentType: 'x-www-form-urlencoded',
      // Fetch the stored token from localStorage and set in the header
      beforeSend: function (xhr) { xhr.setRequestHeader ("Authorization", "Bearer " + sessionStorage.getItem('token')); },
      success: function (result) {
        var returnResult = JSON.stringify(result);
        alert('Success!\n' + returnResult);
        return result;
      },
      error: errorMessage
    });
  });
});

var collapsibles = document.getElementsByClassName("collapsible");
Object.values(collapsibles).forEach(function(collapsible) {
  collapsible.addEventListener("click", function() {
    collapsible.classList.toggle("active");
    var content = collapsible.nextElementSibling
    if (content.style.maxHeight) {
      content.style.maxHeight = null
    } else {
      content.style.maxHeight = content.scrollHeight + "px";
    }
  })
})
