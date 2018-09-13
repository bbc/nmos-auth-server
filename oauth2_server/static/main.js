$(function getToken() {
  console.log("Inside Function");
  $("#token").click(function(){
    var requestPayload = {
      'grant_type': 'password',
      'username': document.getElementById("username").value,
      'password': document.getElementById("password").value,
      'scope': document.getElementById("scope").value
    };
    var username = document.getElementById("client_id").value;
    var password = document.getElementById("client_secret").value;
    $.ajax({
      url: 'http://localhost:5000/oauth/token',
      type: 'POST',
      data: requestPayload,
      crossDomain: true,
      beforeSend: function (xhr) {
        xhr.setRequestHeader ("Authorization", "Basic " + btoa(username + ":" + password));
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
    console.log(localStorage.getItem('token'));
    $.ajax({
      url: 'http://127.0.0.1:5000/api/me',
      type: 'GET',
      contentType: 'x-www-form-urlencoded',
      dataType: 'json',
      // Fetch the stored token from localStorage and set in the header
      beforeSend: function (xhr) { xhr.setRequestHeader ("Authorization", "Bearer " + localStorage.getItem('token')); },
      success: function (result) {
        console.log('Success!');
        var returnResult = JSON.stringify(result);
        document.getElementById('callResults').innerHTML = returnResult;
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
