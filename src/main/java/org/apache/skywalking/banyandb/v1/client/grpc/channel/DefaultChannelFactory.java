/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.skywalking.banyandb.v1.client.grpc.channel;

import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.internal.PlatformDependent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nl.altindag.ssl.pem.util.PemUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import org.apache.skywalking.banyandb.v1.client.Options;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class DefaultChannelFactory implements ChannelFactory {
    private final URI[] targets;
    private final Options options;

    private ZonedDateTime lastModifiedTimeCaFile;
    private X509ExtendedTrustManager swappableTrustManager;

    @Override
    public ManagedChannel create() throws IOException {
        NettyChannelBuilder managedChannelBuilder = NettyChannelBuilder.forAddress(resolveAddress())
                .maxInboundMessageSize(options.getMaxInboundMessageSize())
                .usePlaintext();

        Path caFile = Paths.get(options.getSslTrustCAPath());
        boolean isCAFileExist = Files.exists(caFile) && Files.isRegularFile(caFile);
        if (options.isForceTLS() || isCAFileExist) {
            SslContextBuilder builder = GrpcSslContexts.forClient();

            if (isCAFileExist) {
                BasicFileAttributes caFileAttributes = Files.readAttributes(caFile, BasicFileAttributes.class);
                lastModifiedTimeCaFile = ZonedDateTime.ofInstant(caFileAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC);
                X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(caFile);
                swappableTrustManager = TrustManagerUtils.createSwappableTrustManager(trustManager);
                builder.trustManager(swappableTrustManager);

                Runnable sslUpdater = createSslUpdater();
                ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
                executorService.scheduleAtFixedRate(sslUpdater, 1, 1, TimeUnit.HOURS);
                Runtime.getRuntime().addShutdownHook(new Thread(executorService::shutdown));
            }
            managedChannelBuilder.negotiationType(NegotiationType.TLS).sslContext(builder.build());
        }
        return managedChannelBuilder.build();
    }

    private SocketAddress resolveAddress() throws UnknownHostException {
        int numAddresses = this.targets.length;
        if (numAddresses < 1) {
            throw new UnknownHostException();
        }
        int offset = numAddresses == 1 ? 0 : PlatformDependent.threadLocalRandom().nextInt(numAddresses);
        return new InetSocketAddress(this.targets[offset].getHost(), this.targets[offset].getPort());
    }

    private Runnable createSslUpdater() {
        return () -> {
            try {
                Path caFile = Paths.get(options.getSslTrustCAPath());
                BasicFileAttributes caFileAttributes = Files.readAttributes(caFile, BasicFileAttributes.class);
                if (ZonedDateTime.ofInstant(caFileAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC).isAfter(lastModifiedTimeCaFile)) {
                    X509ExtendedTrustManager trustManager = PemUtils.loadTrustMaterial(caFile);
                    TrustManagerUtils.swapTrustManager(swappableTrustManager, trustManager);
                    lastModifiedTimeCaFile = ZonedDateTime.ofInstant(caFileAttributes.lastModifiedTime().toInstant(), ZoneOffset.UTC);
                    log.info("SSL configuration has been reloaded");
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
    }

}
