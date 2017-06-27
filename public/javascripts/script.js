


$( document ).ready(function() {
	
	
	
	var socket = io();
	socket.on('datos', function(msg){
		$('.appendata').prepend("<h4 class='newdata'> " + msg + "</h4>")
		
	});


	socket.on('black',function(black){
		$('.appendattacks').prepend("<h4 class='newdata'> " + black + "</h4>")
	})

});
