function checkddos($sec) {
$ban=0; $file="protect.dat"; $time=time(); $ip=$_SERVER[REMOTE_ADDR];
$whitelist=array("127.0.0.1","91.42.*.*","217.235.*.*","213.180.*.*","87.250.*.*","77.88.*.*","66.249.*.*","188.72.*.*");
$x=explode(".",$ip); foreach($whitelist as $ip1) if(preg_match("/^$x[0]\.($x[1]|\*)\.($x[2]|\*)\.($x[3]|\*)$/",$ip1)) return 0;
$f=@fopen($file,"r"); if($f) {clearstatcache(); flock($f,LOCK_SH); $r=@fread($f,filesize($file)); fclose($f);}
$a=unserialize($r);
if($a[$ip]+$sec>=$time) $ban=1; $a[$ip]=$time;
foreach($a as $k=>$v) if($v+$sec+1<$time) unset($a[$k]);
file_put_contents($file,serialize($a),LOCK_EX);
return $ban;
}
if(checkddos(1)) { die("Oops..."); exit(); }