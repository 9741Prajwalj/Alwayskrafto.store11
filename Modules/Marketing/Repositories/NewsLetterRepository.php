<?php
namespace Modules\Marketing\Repositories;
use App\Models\Subscription;
use App\Models\User;
use Carbon\Carbon;
use Modules\GeneralSetting\Entities\EmailTemplate;
use Modules\Marketing\Entities\NewsLetter;
use Modules\RolePermission\Entities\Role;
use App\Traits\SendMail;

class NewsLetterRepository {
    use SendMail;
    public function getAll(){
        return NewsLetter::latest();
    }
    public function store($data){
        $user_ids = "";
        if($data['send_to'] == 1){
            $user_ids = json_encode($data['all_user']);
        }
        if($data['send_to'] == 2){
            $user_ids = json_encode(User::where('role_id',$data['role'])->pluck('id'));
            $single_role_id = $data['role'];
        }
        if($data['send_to'] == 3){
            $user_ids = json_encode(User::whereIn('role_id',$data['role_list'])->pluck('id'));
            $multiple_role_id = json_encode($data['role_list']);
        }
        if($data['send_to'] == 4){
            $user_ids = json_encode($data['subscriber_list']);
        }
        $news_letter = new NewsLetter();
        $data['publish_date'] = Carbon::parse($data['publish_date'])->format('Y-m-d');
        $data['send_user_ids'] = $user_ids;
        $data['single_role_id'] = isset($single_role_id)?$single_role_id:null;
        $data['multiple_role_id'] = isset($multiple_role_id)?$multiple_role_id:null;
        $data['send_type'] = $data['send_to'];


        if(isModuleActive('FrontendMultiLang')){
            $news_letter->fill($data)->save();
        }else{
            $news_letter->setTranslation('title','en',$data['title']);
            $news_letter->setTranslation('message','en',$data['message']);
            $news_letter->publish_date = $data['publish_date'];
            $news_letter->send_user_ids = $data['send_user_ids'];
            $news_letter->single_role_id = $data['single_role_id'];
            $news_letter->send_type = $data['send_type'];
            $news_letter->publish_date = $data['publish_date'];
            $news_letter->send_to = $data['send_to'];
            $news_letter->save();
        }

        return $news_letter;
    }

    public function update($data){
        $user_ids = "";
        if($data['send_to'] == 1){
            $user_ids = json_encode($data['all_user']);
        }
        if($data['send_to'] == 2){
            $user_ids = json_encode(User::where('role_id',$data['role'])->pluck('id'));
            $single_role_id = $data['role'];
        }
        if($data['send_to'] == 3){
            $user_ids = json_encode(User::whereIn('role_id',$data['role_list'])->pluck('id'));
            $multiple_role_id = json_encode($data['role_list']);
        }
        if($data['send_to'] == 4){
            $user_ids = json_encode($data['subscriber_list']);
        }
        $data['publish_date'] = Carbon::parse($data['publish_date'])->format('Y-m-d');
        $data['send_user_ids'] = $user_ids;
        $data['single_role_id'] = isset($single_role_id)?$single_role_id:null;
        $data['multiple_role_id'] = isset($multiple_role_id)?$multiple_role_id:null;
        $data['send_type'] = $data['send_to'];
        if(isModuleActive('FrontendMultiLang')){
            $news_letter = NewsLetter::where('id',$data['id'])->first();
            $news_letter->fill($data)->save();
        }else{
            $news_letter = NewsLetter::where('id',$data['id'])->first();
            $news_letter->setTranslation('title','en',$data['title']);
            $news_letter->setTranslation('message','en',$data['message']);
            $news_letter->publish_date = $data['publish_date'];
            $news_letter->send_user_ids = $data['send_user_ids'];
            $news_letter->single_role_id = $data['single_role_id'];
            $news_letter->send_type = $data['send_type'];
            $news_letter->publish_date = $data['publish_date'];
            $news_letter->send_to = $data['send_to'];
            return  $news_letter->save();
        }

    }

    public function testMail($data){
        $message = NewsLetter::findOrFail($data['id']);
        $array['subject'] = $message->title;
        $array['from'] = env('MAIL_USERNAME');
        $array['content'] = $message->message;
        $array['content'] = str_replace('{EMAIL_SIGNATURE}',app('general_setting')->mail_signature,$array['content']);
        $array['content'] = str_replace('{EMAIL_FOOTER}',app('general_setting')->mail_footer,$array['content']);
        $mailPath = '\App\Mail\NewsLetterMail';
        $template = '/backEnd/template';
        $this->sendMailWithTemplate($data['email'],$array,$mailPath,$template);
        return true;
    }
    public function getAllRole(){
        return Role::all();
    }
    public function getAllUser(){
        return User::where('email','!=',null)->get();
    }
    public function getAllSubscriber(){
        return Subscription::all();
    }
    public function getAllActiveSubscriber(){
        if(!app('general_setting')->verify_on_newsletter){
            return Subscription::where('status', 1)->latest()->get();
        }else{
            return Subscription::where('status', 1)->where('is_verified', 1)->latest()->get();
        }
    }
    public function getEmailTemplate(){
        return EmailTemplate::where('type_id', 17)->where('is_active', 1)->first();
    }
    public function getUserByRole($id){
        return User::where('email','!=',null)->where('role_id',$id)->get();
    }
    public function editById($id){
        return NewsLetter::findOrFail($id);
    }
    public function deleteById($id){
        return NewsLetter::findOrFail($id)->delete();
    }
}
