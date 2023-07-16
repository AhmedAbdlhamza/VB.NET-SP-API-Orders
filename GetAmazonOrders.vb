Imports System.Net.Http
Imports System.Text
Imports System.Threading.Tasks

Module Module1
    Sub Main()
        Dim sellerId As String = "YOUR_SELLER_ID"
        Dim accessKeyId As String = "YOUR_ACCESS_KEY_ID"
        Dim secretKey As String = "YOUR_SECRET_KEY"
        Dim marketplaceId As String = "YOUR_MARKETPLACE_ID"
        Dim baseUrl As String = "https://sellingpartnerapi.amazon.com"

        Dim ordersEndpoint As String = baseUrl & "/orders/v0/orders"

        Dim httpClient As HttpClient = New HttpClient()
        httpClient.DefaultRequestHeaders.Add("x-amz-access-token", accessKeyId)

        Dim requestDate As String = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        Dim canonicalUri As String = "/orders/v0/orders"
        Dim canonicalQueryString As String = "MarketplaceIds=" & marketplaceId
        Dim canonicalHeaders As String = "host:" & New Uri(baseUrl).Host & vbLf & "x-amz-access-token:" & accessKeyId & vbLf & "x-amz-date:" & requestDate & vbLf
        Dim signedHeaders As String = "host;x-amz-access-token;x-amz-date"
        Dim payloadHash As String = ComputeSha256Hash("")

        Dim canonicalRequest As String = "GET" & vbLf & canonicalUri & vbLf & canonicalQueryString & vbLf & canonicalHeaders & vbLf & signedHeaders & vbLf & payloadHash
        Dim algorithm As String = "AWS4-HMAC-SHA256"
        Dim region As String = "us-east-1"
        Dim service As String = "execute-api"
        Dim datestamp As String = DateTime.UtcNow.ToString("yyyyMMdd")
        Dim credentialScope As String = datestamp & "/" & region & "/" & service & "/" & "aws4_request"
        Dim stringToSign As String = algorithm & vbLf & requestDate & vbLf & credentialScope & vbLf & ComputeSha256Hash(canonicalRequest)

        Dim signingKey As Byte() = GetSignatureKey(secretKey, datestamp, region, service)
        Dim signature As Byte() = Sign(stringToSign, signingKey)

        Dim signatureString As String = ByteArrayToHexString(signature)
        Dim authorizationHeader As String = algorithm & " Credential=" & accessKeyId & "/" & credentialScope & ", SignedHeaders=" & signedHeaders & ", Signature=" & signatureString

        Dim requestUrl As String = ordersEndpoint & "?" & canonicalQueryString
        Dim requestMessage As HttpRequestMessage = New HttpRequestMessage(HttpMethod.Get, requestUrl)
        requestMessage.Headers.Add("host", New Uri(baseUrl).Host)
        requestMessage.Headers.Add("x-amz-date", requestDate)
        requestMessage.Headers.Add("Authorization", authorizationHeader)

        Dim response As HttpResponseMessage = httpClient.SendAsync(requestMessage).Result
        Dim responseContent As String = response.Content.ReadAsStringAsync().Result

        Console.WriteLine("Response:")
        Console.WriteLine(responseContent)
        Console.ReadLine()
    End Sub

    Function ComputeSha256Hash(ByVal rawData As String) As String
        Using sha256 As Security.Cryptography.SHA256 = Security.Cryptography.SHA256.Create()
            Dim bytes As Byte() = Encoding.UTF8.GetBytes(rawData)
            Dim hashBytes As Byte() = sha256.ComputeHash(bytes)
            Return BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
        End Using
    End Function

    Function GetSignatureKey(ByVal key As String, ByVal dateStamp As String, ByVal regionName As String, ByVal serviceName As String) As Byte()
        Dim kSecret As Byte() = Encoding.UTF8.GetBytes("AWS4" & key)
        Dim kDate As Byte() = Sign(dateStamp, kSecret)
        Dim kRegion As Byte() = Sign(regionName, kDate)
        Dim kService As Byte() = Sign(serviceName, kRegion)
        Dim kSigning As Byte() = Sign("aws4_request", kService)
        Return kSigning
    End Function

    Function Sign(ByVal stringToSign As String, ByVal signingKey As Byte()) As Byte()
        Dim signature As Byte()
        Using hmacSha256 As Security.Cryptography.HMACSHA256 = New Security.Cryptography.HMACSHA256(signingKey)
            Dim bytes As Byte() = Encoding.UTF8.GetBytes(stringToSign)
            signature = hmacSha256.ComputeHash(bytes)
        End Using
        Return signature
    End Function

    Function ByteArrayToHexString(ByVal bytes As Byte()) As String
        Dim result As StringBuilder = New StringBuilder(bytes.Length * 2)
        For Each b As Byte In bytes
            result.Append(b.ToString("x2"))
        Next
        Return result.ToString()
    End Function
End Module

