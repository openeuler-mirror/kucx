/*
 * Copyright (C) Mellanox Technologies Ltd. 2019. ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

package org.openucx.jucx.examples;

import org.openucx.jucx.UcxCallback;
import org.openucx.jucx.ucp.UcpRequest;
import org.openucx.jucx.UcxUtils;
import org.openucx.jucx.ucp.*;


import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class UcxReadBWBenchmarkReceiver extends UcxBenchmark {

    public static void main(String[] args) throws Exception {
        if (!initializeArguments(args)) {
            return;
        }

        createContextAndWorker();

        String serverHost = argsMap.get("s");
        InetSocketAddress sockaddr = new InetSocketAddress(serverHost, serverPort);
        UcpListener listener = worker.newListener(
            new UcpListenerParams().setSockAddr(sockaddr));
        resources.push(listener);

        ByteBuffer recvBuffer = ByteBuffer.allocateDirect(4096);
        UcpRequest recvRequest = worker.recvTaggedNonBlocking(recvBuffer, null);

        System.out.println("Waiting for connections on " + sockaddr + " ...");

        while (!recvRequest.isCompleted()) {
            worker.progress();
        }

        long remoteAddress = recvBuffer.getLong();
        long remoteSize = recvBuffer.getLong();
        int remoteKeySize = recvBuffer.getInt();
        int rkeyBufferOffset = recvBuffer.position();

        recvBuffer.position(rkeyBufferOffset + remoteKeySize);
        int workerAdressSize = recvBuffer.getInt();
        ByteBuffer workerAddress = ByteBuffer.allocateDirect(workerAdressSize);
        copyBuffer(recvBuffer, workerAddress, workerAdressSize);

        int remoteHashCode = recvBuffer.getInt();
        System.out.printf("Received connection. Will read %d bytes from remote address %d%n",
            remoteSize, remoteAddress);

        UcpEndpoint endpoint = worker.newEndpoint(
            new UcpEndpointParams().setUcpAddress(workerAddress).setPeerErrorHadnlingMode());


        recvBuffer.position(rkeyBufferOffset);
        UcpRemoteKey remoteKey = endpoint.unpackRemoteKey(recvBuffer);
        resources.push(remoteKey);

        UcpMemory recvMemory = context.memoryMap(allocationParams);
        resources.push(recvMemory);
        ByteBuffer data = UcxUtils.getByteBufferView(recvMemory.getAddress(),
            (int)Math.min(Integer.MAX_VALUE, totalSize));
        for (int i = 0; i < numIterations; i++) {
            final int iterNum = i;
            UcpRequest getRequest = endpoint.getNonBlocking(remoteAddress, remoteKey,
                recvMemory.getAddress(), totalSize,
                new UcxCallback() {
                    long startTime = System.nanoTime();

                    @Override
                    public void onSuccess(UcpRequest request) {
                        long finishTime = System.nanoTime();
                        data.clear();
                        assert data.hashCode() == remoteHashCode;
                        double bw = getBandwithGbits(finishTime - startTime, remoteSize);
                        System.out.printf("Iteration %d, bandwidth: %.4f GB/s%n", iterNum, bw);
                    }
                });

            while (!getRequest.isCompleted()) {
                worker.progress();
            }
            // To make sure we receive correct data each time to compare hashCodes
            data.put(0, (byte)1);
        }

        ByteBuffer sendBuffer = ByteBuffer.allocateDirect(100);
        sendBuffer.asCharBuffer().put("DONE");
        UcpRequest sent = endpoint.sendTaggedNonBlocking(sendBuffer, null);

        while (!sent.isCompleted()) {
            worker.progress();
        }

        // Close endpoint and wait for remote side
        // TODO remove when UCP close protocol is implemented
        endpoint.close();
        try {
            Thread.sleep(3000);
        } catch (java.lang.InterruptedException e) {
        }

        closeResources();
    }
}
