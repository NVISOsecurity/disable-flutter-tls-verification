import 'dart:typed_data';
import 'package:flutter/services.dart' show rootBundle;
import 'package:dio/adapter.dart';
import 'package:flutter/material.dart';
import 'dart:io';
import 'dart:async';
import 'dart:isolate';
import 'package:dio/dio.dart';
void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Proxy Me',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // Try running your application with "flutter run". You'll see the
        // application has a blue toolbar. Then, without quitting the app, try
        // changing the primarySwatch below to Colors.green and then invoke
        // "hot reload" (press "r" in the console where you ran "flutter run",
        // or simply save your changes to "hot reload" in a Flutter IDE).
        // Notice that the counter didn't reset back to zero; the application
        // is not restarted.
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Proxy me please'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({Key? key, required this.title}) : super(key: key);

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String _status = "Choose";
  late HttpClient client;


  _MyHomePageState(){

  }

  void abortWithError(String e){
    stdout.write('Error:');
    stdout.write(e);
  }

  void callHTTP(){
    client = HttpClient();
    _status = "Calling...";
    client
        .getUrl(Uri.parse('http://neverssl.com')) // produces a request object
        .then((request) => request.close()) // sends the request
        .then((response) => setState((){_status = "HTTP: SUCCESS (" + response.headers.value("date")! + ")" ;}))
        .catchError((e) =>
        setState(() {
          _status = "HTTP: ERROR";
          print(e.toString());
        })
    );

  }
  void callHTTPS(){
    client = HttpClient();
    _status = "Calling...";

    client
        .getUrl(Uri.parse('https://www.nviso.eu')) // produces a request object
        .then((request) => request.close()) // sends the request
        .then((response) => setState((){
      _status = "HTTPS: SUCCESS (" + response.headers.value("date")! + ")" ;
    }))
        .catchError((e) =>
        setState(() {
          _status = "HTTPS: ERROR";
          print(e.toString());
        })
    );

  }

  void callPinnedHTTPS() async {

    ByteData data = await rootBundle.load('raw/certificate.crt');

    client = HttpClient();
    _status = "";
    setState((){
      _status = "";
    });

    Dio dio = Dio();
    (dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate  = (client) {
      SecurityContext sc = new SecurityContext();
      sc.setTrustedCertificatesBytes(data.buffer.asUint8List());
      HttpClient httpClient = new HttpClient(context: sc);
      return httpClient;
    };

    try {
      Response response = await dio.get("https://www.nviso.eu/?dio");
      _status = "HTTPS: SUCCESS (" + response.headers.value("date")! + ")" ;
    } catch (e) {
      print("Request via DIO failed");
      print("Exception: $e");
      _status = "DIO: ERROR";
    }

    setState((){
      _status = _status.trim();
    });

  }



  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
        appBar: AppBar(
          // Here we take the value from the MyHomePage object that was created by
          // the App.build method, and use it to set our appbar title.
          title: Text(widget.title),
        ),
        body: Center(
          // Center is a layout widget. It takes a single child and positions it
          // in the middle of the parent.
          child: Column(
            // Column is also layout widget. It takes a list of children and
            // arranges them vertically. By default, it sizes itself to fit its
            // children horizontally, and tries to be as tall as its parent.
            //
            // Invoke "debug painting" (press "p" in the console, choose the
            // "Toggle Debug Paint" action from the Flutter Inspector in Android
            // Studio, or the "Toggle Debug Paint" command in Visual Studio Code)
            // to see the wireframe for each widget.
            //
            // Column has various properties to control how it sizes itself and
            // how it positions its children. Here we use mainAxisAlignment to
            // center the children vertically; the main axis here is the vertical
            // axis because Columns are vertical (the cross axis would be
            // horizontal).
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[

              TextButton(
                child: Text('HTTP Request',
                  style: TextStyle(fontSize: 32),
                ),
                style: TextButton.styleFrom(
                    primary: Colors.black,

                    backgroundColor: Colors.green
                ),
                onPressed: (){setState(callHTTP);},
              ),
              SizedBox(height: 20),
              TextButton(
                child: Text('HTTPS Request',
                  style: TextStyle(fontSize: 32),
                ),
                style: TextButton.styleFrom(
                    primary: Colors.black,
                    backgroundColor: Colors.orange
                ),
                onPressed: (){setState(callHTTPS);},
              ),
              SizedBox(height: 20),
              TextButton(
                child: Text('Pinned Request',
                    style: TextStyle(fontSize: 32)
                ),
                style: TextButton.styleFrom(
                  primary: Colors.black,
                  backgroundColor: Colors.red,
                ),
                onPressed: (){
                  var response = callPinnedHTTPS();
                },
              ),

              Text(
                'Status:',
                style: Theme.of(context).textTheme.displayMedium,
              ),
              Text(
                '$_status',
                style: Theme.of(context).textTheme.displayMedium,
              ),
            ],
          ),
        )
    );
  }
}

