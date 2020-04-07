vpn<-scan("icmp_TLS_VPN.dat");
no_vpn<-scan("icmp_NO_VPN.dat");
summary(vpn);
summary(no_vpn);
pdf("icmp.pdf", height=4);
plot(ecdf(vpn), verticals=T, do.points=F, main="Cumulative distribution of RTTs", xlab="RTT, ms", ylab="Probability", lwd=3, col="dark blue", xlim=c(0, 300));
plot(ecdf(no_vpn), lwd=3, col="dark red", add=T, verticals=T, do.points=F);
grid(col="black");
legend("bottomright", c("TLS VPN", "Plain TCP"), col=c("dark blue", "dark red"), bty="n", lwd=c(3, 3))
dev.off();

