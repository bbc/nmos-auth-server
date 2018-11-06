$(function getToken() {
  console.log("Inside Function");
  var port = window.location.port;
  var host = window.location.hostname;
  $("#token").click(function(){
    var requestPayload = {
      'grant_type': 'password',
      'username': document.getElementById("username").value,
      'password': document.getElementById("password").value,
      'scope': document.getElementById("scope").value
    };
    // if (requestPayload.scope.split(" ").length > 1) {
    //   alert('Error: Please only provide a single scope');
    //   return false;
    // }
    var client_id = document.getElementById("client_id").value;
    var client_secret = document.getElementById("client_secret").value;
    $.ajax({
      url: 'http://' + host + ':' + port + '/oauth/token',
      type: 'POST',
      data: requestPayload,
      crossDomain: true,
      beforeSend: function (xhr) {
        xhr.setRequestHeader ("Authorization", "Basic " + btoa(client_id + ":" + client_secret));
      },
      //contentType: 'x-www-form-urlencoded',
      //dataType: 'json'
      success: function(data) {
        console.log('Success!');
        var accessToken = data.access_token;
        localStorage.setItem('token', accessToken);
        alert('Success!\nAccess Token:\n' + accessToken);
        return data;
      },
      error: function (XMLHttpRequest, textStatus, errorThrown) {
          console.log(XMLHttpRequest.status + " " + XMLHttpRequest.statusText);
          alert('Error: ' + errorThrown);
          return false;
      }
    });
  });
});


$(function getResource() {
  $("#resource").click(function(){
    console.log("Inside Function");
    var port = window.location.port;
    var host = window.location.hostname;
    console.log(localStorage.getItem('token'));
    $.ajax({
      url: 'http://' + host + ':' + port + '/test',
      type: 'GET',
      contentType: 'x-www-form-urlencoded',
      // Fetch the stored token from localStorage and set in the header
      beforeSend: function (xhr) { xhr.setRequestHeader ("Authorization", "Bearer " + localStorage.getItem('token')); },
      success: function (result) {
        console.log('Success!');
        var returnResult = JSON.stringify(result);
        alert('Success!\n' + returnResult);
        return result;
      },
      error: function (XMLHttpRequest, textStatus, errorThrown) {
        console.log(XMLHttpRequest.status + ' ' + XMLHttpRequest.statusText);
        alert('Error: ' + errorThrown);
        return false;
      }
    });
  });
});
