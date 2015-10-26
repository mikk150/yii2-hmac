<?php
namespace mikk150\hmac;

use yii\base\ActionFilter;
use Yii;

/**
*
*/
class HmacFilter extends ActionFilter
{
    public $key;
    
    public $data;

    public $mac;

    public $security = 'security';

    /**
     * @inheritdoc
     */
    public function beforeAction($action)
    {
        $algo=$this->getSecurity()->macHash;
        $calculcatedHash=hash_hmac($algo, $this->getData($action), $this->getKey($action));
        return $this->getSecurity()->compareString($calculcatedHash, $this->getMac($action));
    }

    private function getData($action)
    {
        if (is_callable($this->data)) {
            return call_user_func($this->data, $action);
        }
        return $this->data;
    }

    private function getKey($action)
    {
        if (is_callable($this->key)) {
            return call_user_func($this->key, $action);
        }
        return $this->key;
    }

    private function getMac($action)
    {
        if (is_callable($this->mac)) {
            return call_user_func($this->mac, $action);
        }
        return $this->mac;
    }

    private function getSecurity()
    {
        return Yii::$app->get($this->security);
    }
}
