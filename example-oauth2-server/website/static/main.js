$(function getToken() {
  console.log("Inside Function");
  $("#token").click(function(){
    var requestPayload = {
                'grant_type': 'password',
                'username': document.getElementById("username").value,
                'password': document.getElementById("password").value,
                'scope': document.getElementById("scope").value
    };
    $.ajax({
      url: 'http://127.0.0.1:5000/oauth/token',
      type: 'POST',
      data: requestPayload,
      dataType: 'json',
      username: 'mpLdzPAchfON4qVCz6GO3o6S',
      password: 'zIEYbZYMvu1XNT1bBurWS1tg0n58j91v5pchfBXOf9iAdzO3',
      //contentType: 'x-www-form-urlencoded',
      error: function (XMLHttpRequest, textStatus, errorThrown) {
          alert('Error: ' + errorThrown);
          console.log(XMLHttpRequest.status + ' ' + XMLHttpRequest.statusText);
          return false;
      },
      success: function(data) {
        accessToken = data.access_token;
        alert('Success!\r\nAccess Token:\r' + accessToken + '\r\n');
        console.log('Success!');
        localStorage.setItem('token', accessToken);
        return data;
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
        var returnResult = JSON.stringify(result);
        alert('Success!\r\n' + returnResult);
        document.getElementById('callResults').innerHTML = returnResult;
        return result;
      },
      error: function (XMLHttpRequest, textStatus, errorThrown) {
          alert('Error: ' + errorThrown);
          console.log(XMLHttpRequest.status + ' ' + XMLHttpRequest.statusText);
          return false;
      }
    });
  });
});
