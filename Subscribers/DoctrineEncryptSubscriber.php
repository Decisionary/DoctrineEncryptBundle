<?php

namespace VMelnik\DoctrineEncryptBundle\Subscribers;
use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Util\ClassUtils;
use \ReflectionClass;
use VMelnik\DoctrineEncryptBundle\Encryptors\AES256Encryptor;
/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber {
    /**
     * Encryptor interface namespace
     */
    const ENCRYPTOR_INTERFACE_NS = 'VMelnik\DoctrineEncryptBundle\Encryptors\EncryptorInterface';
    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'VMelnik\DoctrineEncryptBundle\Configuration\Encrypted';
    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private $encryptor;
    /**
     * Annotation reader
     * @var \Doctrine\Common\Annotations\Reader
     */
    private $annReader;
    /**
     * Secret key
     * @var string
     */
    private $secretKey;
    /**
     * Used for restoring the encryptor after changing it
     * @var string
     */
    private $restoreEncryptor;
    /**
     * Count amount of decrypted values in this service
     * @var integer
     */
    public $decryptCounter = 0;
    /**
     * Count amount of encrypted values in this service
     * @var integer
     */
    public $encryptCounter = 0;
    /**
     * Initialization of subscriber
     *
     * @param Reader $annReader
     * @param string $encryptorClass  The encryptor class.  This can be empty if a service is being provided.
     * @param string $secretKey The secret key.
     * @param EncryptorInterface|NULL $service (Optional)  An EncryptorInterface.
     *
     * This allows for the use of dependency injection for the encrypters.
     */
    public function __construct(Reader $annReader, $encryptorClass, $secretKey, EncryptorInterface $service = NULL) {
        $this->annReader = $annReader;
        $this->secretKey = $secretKey;
        if ($service instanceof EncryptorInterface) {
            $this->encryptor = $service;
        } else {
            $this->encryptor = $this->encryptorFactory($encryptorClass, $secretKey);
        }
        $this->restoreEncryptor = $this->encryptor;
    }
    /**
     * Change the encryptor
     *
     * @param $encryptorClass
     */
    public function setEncryptor($encryptorClass) {
        if(!is_null($encryptorClass)) {
            $this->encryptor = $this->encryptorFactory($encryptorClass, $this->secretKey);
            return;
        }
        $this->encryptor = null;
    }
    /**
     * Get the current encryptor
     */
    public function getEncryptor() {
        if(!empty($this->encryptor)) {
            return get_class($this->encryptor);
        } else {
            return null;
        }
    }
    /**
     * Restore encryptor set in config
     */
    public function restoreEncryptor() {
        $this->encryptor = $this->restoreEncryptor;
    }
    /**
     * Listen a postUpdate lifecycle event.
     * Decrypt entity's property's values when post updated.
     *
     * So for example after form submit the preUpdate encrypted the entity
     * We have to decrypt them before showing them again.
     *
     * @param LifecycleEventArgs $args
     */
    public function postUpdate(LifecycleEventArgs $args) {
        $entity = $args->getEntity();
        $this->processFields($entity, false);
    }
    /**
     * Listen a preUpdate lifecycle event.
     * Encrypt entity's property's values on preUpdate, so they will be stored encrypted
     *
     * @param PreUpdateEventArgs $args
     */
    public function preUpdate(PreUpdateEventArgs $args) {
        $entity = $args->getEntity();
        $this->processFields($entity);
    }
    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entity's property's values when loaded into the entity manger
     *
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args) {
        //Get entity and process fields
        $entity = $args->getEntity();
        $this->processFields($entity, false);
    }
    /**
     * Realization of EventSubscriber interface method.
     *
     * @return Array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents() {
        return array(
          Events::postUpdate,
          Events::preUpdate,
          Events::postLoad,
        );
    }
    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object $entity doctrine entity
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     *
     * @throws \RuntimeException
     *
     * @return object|null
     */
    public function processFields($entity, $isEncryptOperation = true) {
        if(!empty($this->encryptor)) {
            //Check which operation to be used
            $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';
            //Get the real class, we don't want to use the proxy classes
            if(strstr(get_class($entity), "Proxies")) {
                $realClass = ClassUtils::getClass($entity);
            } else {
                $realClass = get_class($entity);
            }
            //Get ReflectionClass of our entity
            $reflectionClass = new ReflectionClass($realClass);
            $properties = $this->getClassProperties($realClass);
            //Foreach property in the reflection class
            foreach ($properties as $refProperty) {
                /**
                 * If followed standards, method name is getPropertyName, the propertyName is lowerCamelCase
                 * So just uppercase first character of the property, later on get and set{$methodName} wil be used
                 */
                $methodName = ucfirst($refProperty->getName());
                /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
                if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {
                    /**
                     * If it is public lets not use the getter/setter
                     */
                    if ($refProperty->isPublic()) {
                        $propName = $refProperty->getName();
                        $entity->$propName = $this->encryptor->$encryptorMethod($refProperty->getValue());
                    } else {
                        //If private or protected check if there is an getter/setter for the property, based on the $methodName
                        if ($reflectionClass->hasMethod($getter = 'get' . $methodName) && $reflectionClass->hasMethod($setter = 'set' . $methodName)) {
                            //Get the information (value) of the property
                            try {
                                $getInformation = $entity->$getter();
                            } catch(\Exception $e) {
                                $getInformation = null;
                            }
                            /**
                             * Then decrypt, encrypt the information if not empty, information is an string and the <ENC> tag is there (decrypt) or not (encrypt).
                             * The <ENC> will be added at the end of an encrypted string so it is marked as encrypted. Also protects against double encryption/decryption
                             */
                            if($encryptorMethod == "decrypt") {
                                if(!is_null($getInformation) and !empty($getInformation)) {
                                    if(substr($getInformation, -5) == "<ENC>") {
                                        $this->decryptCounter++;
                                        $currentPropValue = $this->encryptor->decrypt(substr($getInformation, 0, -5));
                                        $entity->$setter($currentPropValue);
                                    }
                                }
                            } else {
                                if(!is_null($getInformation) and !empty($getInformation)) {
                                    if(substr($entity->$getter(), -5) != "<ENC>") {
                                        $this->encryptCounter++;
                                        $currentPropValue = $this->encryptor->encrypt($entity->$getter());
                                        $entity->$setter($currentPropValue);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return $entity;
        }
        return null;
    }
    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return array
     */
    function getClassProperties($className){
        $reflectionClass = new ReflectionClass($className);
        $properties = $reflectionClass->getProperties();
        $propertiesArray = array();
        foreach($properties as $property){
            $propertyName = $property->getName();
            $propertiesArray[$propertyName] = $property;
        }
        if($parentClass = $reflectionClass->getParentClass()){
            $parentPropertiesArray = $this->getClassProperties($parentClass->getName());
            if(count($parentPropertiesArray) > 0)
                $propertiesArray = array_merge($parentPropertiesArray, $propertiesArray);
        }
        return $propertiesArray;
    }
    /**
     * Encryptor factory. Checks and create needed encryptor
     *
     * @param string $classFullName Encryptor namespace and name
     * @param string $secretKey Secret key for encryptor
     *
     * @return EncryptorInterface
     * @throws \RuntimeException
     */
    private function encryptorFactory($classFullName, $secretKey) {
        $refClass = new \ReflectionClass($classFullName);
        if ($refClass->implementsInterface(self::ENCRYPTOR_INTERFACE_NS)) {
            return new $classFullName($secretKey);
        } else {
            throw new \RuntimeException('Encryptor must implements interface EncryptorInterface');
        }
    }
}