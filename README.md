TUPAS authentication used by Finnish banks for Zend Framework 1

# Example

```php
class IndexController extends Zend_Controller
{

  // ...

  public function authenticateAction()
  {
    // From https://www.op.fi/op?cid=150294058&srcpl=3

    $tupas = new Zend_Service_Tupas();
    $tupas->setAuthenticationKey('Esittelykauppiaansalainentunnus');
    $tupas->setServiceUrl('https://kultaraha.op.fi/cgi-bin/krcgi');
    $tupas->setVersion('0003');
    $tupas->setCustomerCode('Esittelymyyja');
    $tupas->setLanguageCode('FI');
    $tupas->setRequestId('20010125140015123456');
    $tupas->setIdentificationType(Zend_Service_Tupas::IDTYPE_BASIC, Zend_Service_Tupas::IDTYPE_FORM_PLAINTEXT);
    $tupas->setReturnUrl('https://your.domain/return/type/success');
    $tupas->setCancelUrl('https://your.domain/return/type/cancel');
    $tupas->setRejectedUrl('https://your.domain/return/type/rejected');
    $tupas->setKeyVersion('0001');
    $tupas->setAlgorithm(Zend_Service_Tupas::ALGORITHM_MD5);

    $form = $tupas->getForm();

    $e = new Zend_Form_Element_Submit('submit');
    $e->setLabel('Submit');
    $form->addElement($e);

    $this->view->form = $form;

    /* And in authenticate.phtml:
     * <?php echo $this->form;
     */
  }

  public function returnAction()
  {
    $tupas = new Zend_Service_Tupas();
    $tupas->setAuthenticationKey('Esittelykauppiaansalainentunnus');

    $valid = $tupas->isValid($_GET);

    if ($valid)
    {
      echo 'valid';
    }
    else
    {
      echo 'not valid';
    }
  }

}

´´´
