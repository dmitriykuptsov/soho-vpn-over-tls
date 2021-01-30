vpn<-scan("results_TLS_VPN.dat");
no_vpn<-scan("results_NO_VPN.dat");
no_vpn<-1.3*8/no_vpn*1024;
vpn<-1.3*8/vpn*1024;
summary(vpn);
summary(no_vpn);
pdf("throughput.pdf", height=4);
plot(ecdf(vpn), verticals=T, do.points=F, xlim=c(0, 2100), main="Cumulative distribution of throughputs", xlab="Throughput, Kb/s", ylab="Probability", lwd=3, col="dark blue");
plot(ecdf(no_vpn), lwd=3, col="dark red", add=T, verticals=T, do.points=F);
grid(col="black");
legend("bottomright", c("TLS VPN", "Plain TCP"), col=c("dark blue", "dark red"), bty="n", lwd=c(3, 3))
dev.off();

