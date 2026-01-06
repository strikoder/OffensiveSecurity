<!-- 
Source: https://github.com/teambi0s/dfunc-bypasser  
Referenced in: HackTheBox UpDown machine  
Video walkthrough: https://youtu.be/yW_lxWB1Yd0?si=zhKMM9pe-3Q12JL2&t=1851  

Note (easier way): The array from this script can be compared with the "disable_functions" value 
shown in phpinfo() if you have access to phpinfo() on the target.
-->
<?php
$dangerous_functions = array(
    'pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait','pcntl_wifexited',
    'pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued','pcntl_wexitstatus',
    'pcntl_wtermsig','pcntl_wstopsig','pcntl_signal','pcntl_signal_get_handler',
    'pcntl_signal_dispatch','pcntl_get_last_error','pcntl_strerror','pcntl_sigprocmask',
    'pcntl_sigwaitinfo','pcntl_sigtimedwait','pcntl_exec','pcntl_getpriority',
    'pcntl_setpriority','pcntl_async_signals','error_log','system','exec','shell_exec',
    'popen','proc_open','passthru','link','symlink','syslog','ld','mail','mb_send_mail',
    'imap_open','imap_mail','libvirt_connect','gnupg_init','imagick',
    // extra execution-related functions
    'assert','create_function','dl','unserialize','expect_popen','ssh2_exec',
    'preg_replace','mb_ereg_replace','FFI','eval','passthru','curl_exec','shell','fsockopen'
);

foreach ($dangerous_functions as $function) 
{
    if (function_exists($function)) 
    {
        echo $function . " is enabled\n";
    }
}
?>
