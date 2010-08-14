<?php
/**
 * TUPAS authentication for Zend Framework
 * TUPAS is used by Finnish banks and government
 * 
 * @see http://www.fkl.fi/www/page/fk_www_4388
 * @see http://www.fkl.fi/www/page/fk_www_3830
 *
 *
 * Pekka Järvinen 2010
 * http://github.com/raspi/zf-tupas
 */
class Zend_Service_Tupas
{
  const                   IDTYPE_BASIC = '0';
  const                IDTYPE_PERSONAL = '1';
  const              IDTYPE_BUSINESSID = '2';
  const  IDTYPE_PERSONAL_OR_BUSINESSID = '3';
  const IDTYPE_PERSONAL_AND_BUSINESSID = '4';

  const IDTYPE_FORM_ENCRYPTED = '1';
  const IDTYPE_FORM_PLAINTEXT = '2';
  const IDTYPE_FORM_TRUNCATED = '3';
  
  const    ALGORITHM_MD5 = '01';
  const   ALGORITHM_SHA1 = '02';
  const ALGORITHM_SHA256 = '03';

  /**
   * @var Zend_Service_Tupas_Identification_Form
   */
  protected $_form = null;

  /**
   * @var string
   */
  protected $_key = '';

  /**
   * 
   */
  public function __construct()
  {
    $this->_form = new Zend_Service_Tupas_Identification_Form();
  }

  /**
   *
   */
  public function setAuthenticationKey($key)
  {
    $this->_key = $key;
  }

  /**
   * URL to bank
   * @param string $serviceUrl
   */
  public function setServiceUrl($serviceUrl)
  {
    $this->_form->setAction($serviceUrl);
  }

  /**
   *
   * @param string $version
   */
  public function setVersion($version)
  {
    $this->_form->getElement('A01Y_VERS')->setValue($version);
  }
  
  /**
   *
   */
  public function setKeyVersion($version)
  {
    $this->_form->getElement('A01Y_KEYVERS')->setValue($version);
  }


  /**
   *
   */
  public function setCustomerCode($customerCode)
  {
    $this->_form->getElement('A01Y_RCVID')->setValue($customerCode);
  }

  /**
   *
   */
  public function setLanguageCode($languageCode)
  {
    $this->_form->getElement('A01Y_LANGCODE')->setValue(strtoupper($languageCode));
  }

  /**
   *
   */
  public function setRequestId($id)
  {
    $this->_form->getElement('A01Y_STAMP')->setValue($id);
  }

  /**
   *
   */
  public function setIdentificationType($type, $form)
  {
    $this->_form->getElement('A01Y_IDTYPE')->setValue($type . $form);
  }

  /**
   *
   */
  public function setAlgorithm($type)
  {
    $this->_form->getElement('A01Y_ALG')->setValue($type);
  }


  /**
   *
   */
  public function setReturnUrl($url)
  {
    $this->_form->getElement('A01Y_RETLINK')->setValue($url);
  }

  /**
   *
   */
  public function setCancelUrl($url)
  {
    $this->_form->getElement('A01Y_CANLINK')->setValue($url);
  }

  /**
   *
   */
  public function setRejectedUrl($url)
  {
    $this->_form->getElement('A01Y_REJLINK')->setValue($url);
  }


  /**
   * @return Zend_Service_Tupas_Identification_Form
   */
  public function getForm()
  {
    $elements = $this->_form->getElements();
    $data = array();
    $check = array();

    foreach($elements as $element)
    {
      $name = $element->getName();
      if (preg_match('@^A01Y_@', $name))
      {
        if ($name === 'A01Y_MAC') {continue;}
        $check[] = $element->getValue();
      }

    }

    $algorithm = $this->_form->getElement('A01Y_ALG')->getValue();
    $checkSum = $this->_generateChecksum($check, $algorithm);

    $this->_form->getElement('A01Y_MAC')->setValue($checkSum);

    foreach($elements as $element)
    {
      $name = $element->getName();
      $data[$name] = $element->getValue();
    }

    $this->_form->isValid($data);
    return $this->_form;
  }

  
  /**
   * @param array $array
   * @param const $algorithm self::ALGORITHM_*
   * @return string
   */
  protected function _generateChecksum(array $data, $algorithm = self::ALGORITHM_MD5)
  {
    if (count($data) > 0)
    {
      $data[] = $this->_key;
    }

    $checkString = join('&', $data) . '&';

    switch($algorithm)
    {
      default: // Default to MD5 so that secret key is not exposed
      case self::ALGORITHM_MD5:
        $checkSum = md5($checkString);
      break;
  
      case self::ALGORITHM_SHA1:
        $checkSum = sha1($checkString);
      break;

      case self::ALGORITHM_SHA256:
        if (false === function_exists('mhash'))
        {
          throw new Zend_Service_Tupas_Exception('SHA256 requires mhash extension');
        }

        $checkSum = bin2hex(mhash(MHASH_SHA256, $checkString));
      break;
    }

    return strtoupper($checkSum);
  }

  /**
   * Validate return
   */
  public function isValid(array $data)
  {
    $check = array();

    foreach($data as $key => $value)
    {
      if (preg_match('@^B02K_@', $key))
      {
        if ($key === 'B02K_MAC') {continue;}
        $check[] = $value;
      }
    }

    if (0 === count($check))
    {
      return false;
    }

    if(array_key_exists('B02K_ALG', $data))
    {
      $algorithm = $data['B02K_ALG'];
    }
    else
    {
      $algorithm = self::ALGORITHM_MD5;
    }

    $checksum = $this->_generateChecksum($check, $algorithm);

    if ($checksum === $data['B02K_MAC'])
    {
      return true;
    }

    return false;
  }

}

/**
 * TUPAS authentication form
 *
 * All fields are hidden and required
 * Field label and errors are shown if element contains errors
 */
class Zend_Service_Tupas_Identification_Form extends Zend_Form
{
  public function init()
  {
    parent::init();

    $this->setMethod(Zend_Form::METHOD_POST);

    // Message type
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_ACTION_ID');
    $e->setLabel('Message type');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 3, 'max' => 4)));
    $e->setValue('701');
    $this->addElement($e);
    unset($e);

    // Version
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_VERS');
    $e->setLabel('Version');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 4, 'max' => 4)));
    $e->setValue('0002');
    $this->addElement($e);
    unset($e);

    // Service provider customer code
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_RCVID');
    $e->setLabel('Service provider customer code');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 10, 'max' => 15)));
    $this->addElement($e);
    unset($e);

    // Service language (ISO 639)
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_LANGCODE');
    $e->setLabel('Service language (ISO 639)');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 2, 'max' => 2)));
    $e->addFilter(new Zend_Filter_StringToUpper());
    $e->setValue('EN');
    $this->addElement($e);
    unset($e);

    // Request identifier
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_STAMP');
    $e->setLabel('Request identifier');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 20, 'max' => 20)));
    $now = new DateTime();
    $e->setValue($now->format('YmdHisu'));
    $this->addElement($e);
    unset($e);

    // Identifier type
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_IDTYPE');
    $e->setLabel('Identifier type');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 2, 'max' => 2)));
    $e->addValidator(new Zend_Service_Tupas_Identifier_Type_Validator());
    $this->addElement($e);
    unset($e);

    // Return address
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_RETLINK');
    $e->setLabel('Return address');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 13, 'max' => 199)));
    $this->addElement($e);
    unset($e);

    // Cancel address
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_CANLINK');
    $e->setLabel('Cancel address');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 13, 'max' => 199)));
    $this->addElement($e);
    unset($e);

    // Rejected address
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_REJLINK');
    $e->setLabel('Rejected address');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 13, 'max' => 199)));
    $this->addElement($e);
    unset($e);

    // Key version
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_KEYVERS');
    $e->setLabel('Key version');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 4, 'max' => 4)));
    $this->addElement($e);
    unset($e);

    // Algorithm
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_ALG');
    $e->setLabel('Algorithm');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 2, 'max' => 2)));
    $e->addValidator(new Zend_Service_Tupas_Algorithm_Type_Validator());
    $e->setValue(Zend_Service_Tupas::ALGORITHM_MD5);
    $this->addElement($e);
    unset($e);

    // Control field
    // Message authentication code of the request
    $e = new Zend_Service_Tupas_Identification_Element('A01Y_MAC');
    $e->setLabel('Message authentication code of the request');
    $e->addValidator(new Zend_Validate_StringLength(array('min' => 32, 'max' => 64)));
    $this->addElement($e);
    unset($e);

  }
}

/**
 *
 */
class Zend_Service_Tupas_Exception extends Zend_Service_Exception
{

}

/**
 * Validate for correct identification type combination
 */
class Zend_Service_Tupas_Identifier_Type_Validator extends Zend_Validate_Abstract
{
  const NOT_VALID = 'notValid';
  const NOT_VALID_COMBINATION = 'notValidCombination';

  protected $_messageTemplates = array(
    self::NOT_VALID => 'Not valid',
    self::NOT_VALID_COMBINATION => 'Not valid combination'
  );

  /**
   *
   */
  public function isValid($value, $context = null)
  {
    $this->_setValue($value);

    if (false === (strlen($value) === 2))
    {
      $this->_error(self::NOT_VALID);
      return false;
    }

    list($type, $form) = str_split($value);

    if (!in_array($type, array(Zend_Service_Tupas::IDTYPE_BASIC, Zend_Service_Tupas::IDTYPE_PERSONAL, Zend_Service_Tupas::IDTYPE_BUSINESSID, Zend_Service_Tupas::IDTYPE_PERSONAL_OR_BUSINESSID, Zend_Service_Tupas::IDTYPE_PERSONAL_AND_BUSINESSID)))
    {
      $this->_error(self::NOT_VALID);
      return false;
    }

    if (!in_array($form, array(Zend_Service_Tupas::IDTYPE_FORM_ENCRYPTED, Zend_Service_Tupas::IDTYPE_FORM_PLAINTEXT, Zend_Service_Tupas::IDTYPE_FORM_TRUNCATED)))
    {
      $this->_error(self::NOT_VALID);
      return false;
    }

    if ($type === Zend_Service_Tupas::IDTYPE_PERSONAL_AND_BUSINESSID && $form === Zend_Service_Tupas::IDTYPE_FORM_TRUNCATED)
    {
      $this->_error(self::NOT_VALID_COMBINATION);
      return false;
    }

    return true;

  }
}

/**
 * Validate algorithm type
 */
class Zend_Service_Tupas_Algorithm_Type_Validator extends Zend_Validate_Abstract
{
  const NOT_VALID = 'notValid';

  protected $_messageTemplates = array(
    self::NOT_VALID => 'Not valid',
  );

  /**
   *
   */
  public function isValid($value, $context = null)
  {
    $this->_setValue($value);

    if (in_array($value, array(Zend_Service_Tupas::ALGORITHM_MD5, Zend_Service_Tupas::ALGORITHM_SHA1, Zend_Service_Tupas::ALGORITHM_SHA256)))
    {
      return true;
    }

    $this->_error(self::NOT_VALID);
    return false;

  }
}


/**
 * 
 */
class Zend_Service_Tupas_Identification_Element extends Zend_Form_Element_Hidden
{
  /**
   *
   */
  public function init()
  {
    parent::init();
    $this->setRequired(true);
  }

  /**
   *
   */
  public function isValid($value, $context = null)
  {
    $valid = parent::isValid($value, $context);

    if ($valid)
    {
      // All fields are hidden when correct
      $this->removeDecorator('HtmlTag');
      $this->removeDecorator('row');
      $this->removeDecorator('label');
    }

    return $valid;
  }
}
