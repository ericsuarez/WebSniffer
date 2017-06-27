var sse = new ServerSentEvent('events');

sse.on('test', function (data) {
	console.log('test', data);
});

sse.on('message', function (data) {
	console.log('message', data);
});
