#javac -d ./build -classpath bcprov-jdk18on-172.jar crypto/*.java #*.java
#cd build
#jar cvf crypto.jar *
#cd ../
#javac -classpath crypto.jar *.java #*.java
cd ../
find . -name "*.java" > sources.txt
javac -classpath bcprov-jdk18on-172.jar @sources.txt #*.java

