# XSS-ON-MY-WAY-
Cross-site scripting (XSS) is a security vulnerability typically found in old and modren Web pages and Mobile Application. XSS enables malicious code like ! @ ~ # $ % ^ & * () _ + {} | : " > ? / . , ; ' [] \ ` -)  for xss attack on website and attackers used malicious strings and character to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy (SOP), Content Security Policy (CSP), Web Application Firewall (WAF) .

# How to Prevent and check xss?
There is still a security issue with this function, according to OWASP the following characters should be filtered in order to prevent an XSS attack:


 1.  & --> &
 2.  < > 
 3.  --> >
 4.  " --> "
 5.  ' --> '     ' is not recommended
 6.  / --> /     forward slash is included as it helps end an HTML entity 
 
 
 With filter_xss() the system is only filtering "&", "<" and ">", leaving holes for other types of javascript code that can be sent through a parameter. For example letting it pass quotes (") allows events like onClick, among others, to be executed successfully:


http://example.com/?q=" onmouseover=prompt("Sujeet")""


For the time being I've hacked the core module filter.module with the same code used to filter "&", but I would like to know if this is the correct approach, and if so, to see this being put in a patch.

 $string = str_replace('"', '"', $string); 
 $string = str_replace("'", ''', $string);
 $string = str_replace('/', '/', $string); 
 
 
#Filters an HTML string to prevent cross-site-scripting (XSS) vulnerabilities.
 
This code does four things:

1. Removes characters and constructs that can trick browsers.
2. Makes sure all HTML entities are well-formed.
3. Makes sure all HTML tags and attributes are well-formed.
4. Makes sure no HTML tags contain URLs with a disallowed protocol (e.g. javascript:).


#Parameters
$string: The string with raw HTML in it. It will be stripped of everything that can cause an XSS attack.

$allowed_tags: An array of allowed tags.

#Return value
An XSS safe version of $string, or an empty string if $string is not valid UTF-8.


#Code

function filter_xss($string, $allowed_tags = array(
  'a',
  'em',
  'strong',
  'cite',
  'code',
  'ul',
  'ol',
  'li',
  'dl',
  'dt',
  'dd',
)) {


1.   // Only operate on valid UTF-8 strings. This is necessary to prevent cross
  // site scripting issues on Internet Explorer 6.
  if (!drupal_validate_utf8($string)) {
    return '';
  }


2.  // Store the input format
  _filter_xss_split($allowed_tags, TRUE);


3.  // Remove NUL characters (ignored by some browsers)
  $string = str_replace(chr(0), '', $string);


4.  // Remove Netscape 4 JS entities
  $string = preg_replace('%&\\s*\\{[^}]*(\\}\\s*;?|$)%', '', $string);


5.  // Defuse all HTML entities
  $string = str_replace('&', '&amp;', $string);


6.  // Change back only well-formed entities in our whitelist
  // Decimal numeric entities
  $string = preg_replace('/&amp;#([0-9]+;)/', '&#\\1', $string);


7.  // Hexadecimal numeric entities
  $string = preg_replace('/&amp;#[Xx]0*((?:[0-9A-Fa-f]{2})+;)/', '&#x\\1', $string);


 8. // Named entities
 
 
  $string = preg_replace('/&amp;([A-Za-z][A-Za-z0-9]*;)/', '&\\1', $string);
  return preg_replace_callback('%
    (
    <(?=[^a-zA-Z!/])  # a lone <
    
    |                 # or
    
    <!--.*?-->        # a comment
    
    |                 # or
    
    <[^>]*(>|$)       # a string that starts with a <, up until the > or the end of the string
    
    |                 # or
    
    >                 # just a >
    
    )%x', '_filter_xss_split', $string);
