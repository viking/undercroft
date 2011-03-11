import java.io.IOException
import java.net.URL
import java.net.MalformedURLException
import java.util.ArrayList
import java.lang.StringBuilder
import java.lang.Character
import java.lang.ClassCastException
import java.lang.RuntimeException
import java.lang.InterruptedException
import java.util.regex.Pattern

import javax.servlet.ServletException
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.ServletHolder
import org.eclipse.jetty.servlet.ServletContextHandler

import org.jsoup.Jsoup
import org.jsoup.nodes.Document

import javax.crypto.spec.PBEParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.Cipher

import java.security.NoSuchAlgorithmException
import java.security.InvalidKeyException
import java.security.InvalidAlgorithmParameterException
import java.security.spec.InvalidKeySpecException
import javax.crypto.NoSuchPaddingException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException

class UndercroftServlet < HttpServlet
  def initialize(url:String, secret:String)
    throws RuntimeException

    begin
      @url = URL.new(url)
    rescue MalformedURLException => e
      raise RuntimeException, e.getMessage
    end
    @secret = secret

    salt = "roflsaur".getBytes
    count = 1
    pbe_param_spec = PBEParameterSpec.new(salt, count)
    pbe_key_spec = PBEKeySpec.new(secret.toCharArray)

    begin
      key_fac = SecretKeyFactory.getInstance("PBEWithMD5AndDES")
    rescue NoSuchAlgorithmException => e
      raise RuntimeException, e.getMessage
    end

    begin
      pbe_key = key_fac.generateSecret(pbe_key_spec)
    rescue InvalidKeySpecException => e
      raise RuntimeException, e.getMessage
    end

    begin
      @pbe_encryption_cipher = Cipher.getInstance("PBEWithMD5AndDES")
      @pbe_decryption_cipher = Cipher.getInstance("PBEWithMD5AndDES")
    rescue NoSuchAlgorithmException, NoSuchPaddingException => e
      raise RuntimeException, e.getMessage
    end

    begin
      @pbe_encryption_cipher.init(Cipher.ENCRYPT_MODE, pbe_key, pbe_param_spec)
      @pbe_decryption_cipher.init(Cipher.DECRYPT_MODE, pbe_key, pbe_param_spec)
    rescue InvalidKeyException, InvalidAlgorithmParameterException => e
      raise RuntimeException, e.getMessage
    end
  end

  def doGet(request:HttpServletRequest, response:HttpServletResponse):void
    throws ServletException, IOException

    response.setContentType("text/html")
    response.setStatus(HttpServletResponse.SC_OK)

    doc = Jsoup.connect(@url.toString).get
    transformDocument(doc)
    response.getWriter.print(doc.toString)
  end

  def doPost(request:HttpServletRequest, response:HttpServletResponse):void
    throws ServletException, IOException

    # prepare to re-post to real url
    conn = Jsoup.connect(request.getParameter('_original_action'))

    # sort out which parameters are in the post body, since HttpServletRequest
    # doesn't distinguish between query params and post params
    # (see http://stackoverflow.com/questions/1197729/retrieve-post-parameters-only-java)
    #
    # FIXME: this is naive, what if there's a post param with the same name
    #        as a query param?
    qparams = ArrayList.new
    query = request.getQueryString
    if query
      pairs = query.split("&")
      i = 0
      while i < pairs.length
        pair = pairs[i]
        arr = pair.split("=")
        qparams.add(arr[0])
        i += 1
      end
    end

    names = request.getParameterNames
    while names.hasMoreElements
      name = String(names.nextElement)
      if qparams.indexOf(name) == -1 && name.compareTo("_original_action") != 0
        # FIXME: also naive, use getParameterValues instead
        value = encrypt(request.getParameter(name))
        conn.data(name, value)
      end
    end

    doc = conn.post
    transformDocument(doc)

    response.setContentType("text/html")
    response.setStatus(HttpServletResponse.SC_OK)
    response.getWriter.print(doc.toString)
  end

  def transformDocument(doc:Document)
    # first try to decrypt any data
    elts = doc.select(":matchesOwn(\\{\\{[0-9a-f]+\\}\\})")
    if elts.size > 0
      p = Pattern.compile("\\{\\{([0-9a-f]+)\\}\\}")
      i = 0
      while i < elts.size
        sb = StringBuilder.new
        elt = elts.get(i)
        html = elt.html
        m = p.matcher(html)
        prev = 0
        while m.find
          sb.append(html.substring(prev, m.start))
          prev = m.end
          sb.append(decrypt(m.group(1)))
        end
        sb.append(html.substring(prev))
        elt.html(sb.toString)
        i += 1
      end
    end

    # rewrite form urls
    elts = doc.select("form")
    i = 0
    while i < elts.size
      elt = elts.get(i)

      begin
        action = URL.new(@url, elt.attr('action'))
      rescue MalformedURLException => e
        raise RuntimeException, e.getMessage
      end

      elt.append("<input type='hidden' name='_original_action' value='#{action.toString}' />")
      elt.attr('action', '/post')
      i += 1
    end
    doc
  end

  def encrypt(str:String)
    throws RuntimeException

    begin
      bytes = @pbe_encryption_cipher.doFinal(str.getBytes)
    rescue IllegalBlockSizeException, BadPaddingException => e
      raise RuntimeException, e.getMessage
    end

    '{{' + String.new(Hex.encodeHex(bytes)) + '}}'
  end

  def decrypt(str:String)
    throws RuntimeException

    bytes = Hex.decodeHex(str.toCharArray)
    begin
      String.new(@pbe_decryption_cipher.doFinal(bytes))
    rescue IllegalBlockSizeException, BadPaddingException => e
      raise RuntimeException, e.getMessage
    end
  end
end

class UndercroftServer
  def initialize(url:String, secret:String)
    server = Server.new(8080)

    context = ServletContextHandler.new(ServletContextHandler.SESSIONS)
    context.setContextPath("/")
    server.setHandler(context)

    servlet = UndercroftServlet.new(url, secret)
    context.addServlet(ServletHolder.new(servlet), "/*")

    begin
      server.start
    rescue Exception => e
      puts "Couldn't start server: #{e.getMessage}"
    end

    begin
      server.join
    rescue InterruptedException => e
      puts "Couldn't join server: #{e.getMessage}"
    end
  end
end

# ganked from http://www.java2s.com/Code/Java/Data-Type/Hexencoderanddecoder.htm
class Hex
  # workaround, see http://groups.google.com/group/mirah/browse_thread/thread/61ca5f5cb41e48fa
  def self.digits
    "0123456789abcdef".toCharArray
  end

  def self.decodeHex(data:char[])
    throws RuntimeException

    len = data.length

    if (len & 0x01) != 0
      raise RuntimeException, "Odd number of characters."
    end

    out = byte[len >> 1]

    i = j = 0
    while j < len
      f = toDigit(data[j], j) << 4
      j += 1
      f = f | toDigit(data[j], j)
      j += 1
      out[i] = byte(f & 0xFF)
      i += 1
    end

    out
  end

  def self.toDigit(ch:char, index:int)
    throws RuntimeException

    digit = Character.digit(ch, 16)
    if digit == -1
      raise RuntimeException, "Illegal hexadecimal charcter #{ch} at index #{index}"
    end

    digit
  end

  def self.encodeHex(data:byte[])
    l = data.length

    out = char[l << 1]

    i = j = 0
    while i < l
      # NOTE: originally this code uses the >>> operator, which is an
      #       unsigned right shift
      out[j] = digits[((0xF0 & data[i]) >> 4) % 16]
      j += 1
      out[j] = digits[0x0F & data[i]]
      j += 1
      i += 1
    end

    out
  end

  def decode(array:byte[])
    throws RuntimeException
    Hex.decodeHex(String.new(array).toCharArray)
  end

  def decode(string:String)
    throws RuntimeException
    Hex.decodeHex(string.toCharArray)
  end

  def decode(object:Object)
    throws RuntimeException

    begin
      charArray = char[].cast(object)
      Hex.decodeHex(charArray)
    rescue ClassCastException => e
      raise RuntimeException, e.getMessage
    end
  end

  def encode(array:byte[])
    String.new(Hex.encodeHex(array)).getBytes
  end

  def encode(string:String)
    Hex.encodeHex(string.getBytes)
  end

  def encode(object:Object)
    throws RuntimeException

    begin
      byteArray = byte[].cast(object)
      Hex.encodeHex(byteArray);
    rescue ClassCastException => e
      raise RuntimeException, e.getMessage
    end
  end
end

UndercroftServer.new("http://localhost:4567", "foobarbaz")
