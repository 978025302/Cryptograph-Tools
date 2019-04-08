Bouncy Castle配置
把jar文件复制到 $JAVA_HOME$\jre\lib\ext 目录下面
修改配置文件\jre\lib\security\java.security\
末尾添加security.provider.x=org.bouncycastle.jce.provider.BouncyCastleProvider
x是下一个值