
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import javax.net.ssl.SSLException;
import javax.security.cert.X509Certificate;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class NettyTcpClient {

    private static final String HOSTNAME = "hardenize.com";

    private static final String IP_ADDRESS = "104.17.158.13";

    private static final int PORT = 443;

    public static void main(String[] args) throws InterruptedException, SSLException {
        // Configure Netty client.

        SslContext sslContext =
                SslContextBuilder.forClient()
                        .sslProvider(SslProvider.OPENSSL)
                        .trustManager(InsecureTrustManagerFactory.INSTANCE)
                        .startTls(false)
                        .protocols("TLSv1.3", "TLSv1.2")
                        .build();

        CountDownLatch latch = new CountDownLatch(1);

        EventLoopGroup group = new NioEventLoopGroup(1);
        Bootstrap bootstrap = new Bootstrap()
                .group(group)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 1_000)
                .handler(new ChannelInitializer<SocketChannel>() {

                    @Override
                    public void initChannel(SocketChannel ch) {
                        if (sslContext != null) {
                            SslHandler sslHandler = sslContext.newHandler(ch.alloc(), HOSTNAME, PORT);
                            if (sslHandler.engine() instanceof ReferenceCountedOpenSslEngine) {
                                // If using custom netty/netty-tcnative.
                                //((ReferenceCountedOpenSslEngine) sslHandler.engine()).setGroupsList("P-256:X25519");
                                //((ReferenceCountedOpenSslEngine) sslHandler.engine()).setSigAlgsList("RSA+SHA256:RSA-PSS+SHA256");
                            }
                            ch.pipeline().addLast("SSL", sslHandler);
                        }

                        ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                            @Override
                            public void channelActive(ChannelHandlerContext ctx) {
                                InetSocketAddress a = (InetSocketAddress) ctx.channel().remoteAddress();
                                System.out.println("# Open port: " + a.getAddress() + ":" + a.getPort());

                                // If we're not going to negotiate TLS, we can
                                // close the connection straight away.
                                if (sslContext == null) {
                                    ctx.close();
                                }
                            }

                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) {
                                latch.countDown();
                            }

                            @Override
                            public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                                // System.out.println("# event: " + evt.getClass().getName());
                                if (evt instanceof SslHandshakeCompletionEvent) {
                                    SslHandler sslhandler = (SslHandler) ctx.channel().pipeline().get("SSL");
                                    System.out.println("# Protocol: " + sslhandler.engine().getSession().getProtocol());
                                    System.out.println("# Cipher suite: " + sslhandler.engine().getSession().getCipherSuite());
                                    System.out.println("# Certificates: " + sslhandler.engine().getSession().getPeerCertificateChain().length);

                                    if (sslhandler.engine().getSession().getPeerCertificateChain().length >= 1) {
                                        X509Certificate c = sslhandler.engine().getSession().getPeerCertificateChain()[0];
                                        System.out.println("# Leaf subject: " + c.getSubjectDN());
                                        System.out.println("# Leaf key: " + c.getSigAlgName());
                                    }

                                    ctx.close();
                                }
                            }
                        });
                    }
                });

        // Open individual connections.

        ChannelFuture f = bootstrap.connect(IP_ADDRESS, PORT);

        /*
        ChannelFuture f = bootstrap.connect("104.17.158.13", 443).addListener(new ChannelFutureListener() {
            @Override
            public void operationComplete(ChannelFuture future) {
                // Can use ChannelFuture#isSuccess here if necessary to
                // determine if the operation has been successful.
                latch.countDown();
            }
        });
         */

        // Await completion and terminate.

        latch.await();
        group.shutdownGracefully(0, 1, TimeUnit.MILLISECONDS);
    }
}
