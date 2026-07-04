package com.hopae.eudi.wallet.vci

import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest as JdkRequest
import java.net.http.HttpResponse as JdkResponse
import java.time.Duration

/**
 * Test-only HttpTransport over java.net.http, used for live interop against issuer.eudiw.dev.
 * Redirects are NOT followed (OpenID flows need to intercept them).
 */
class JdkHttpTransport : HttpTransport {

    private val client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(15))
        .build()

    override suspend fun execute(request: HttpRequest): HttpResponse {
        val builder = JdkRequest.newBuilder(URI.create(request.url)).timeout(Duration.ofSeconds(20))
        val bodyPublisher =
            if (request.body != null) JdkRequest.BodyPublishers.ofByteArray(request.body)
            else JdkRequest.BodyPublishers.noBody()
        when (request.method) {
            HttpMethod.GET -> builder.GET()
            HttpMethod.POST -> builder.POST(bodyPublisher)
            HttpMethod.PUT -> builder.PUT(bodyPublisher)
            HttpMethod.PATCH -> builder.method("PATCH", bodyPublisher)
            HttpMethod.DELETE -> builder.DELETE()
        }
        request.headers.forEach { (k, v) -> builder.header(k, v) }

        val response = client.send(builder.build(), JdkResponse.BodyHandlers.ofByteArray())
        val headers = response.headers().map().entries.flatMap { (k, vs) -> vs.map { k to it } }
        return HttpResponse(response.statusCode(), headers, response.body())
    }
}
