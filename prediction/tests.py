from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core import mail
from django.contrib.messages import get_messages

class SignUpTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def test_successful_signup(self):
        response = self.client.post(reverse('signup'), {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'strongpassword',
            'confirm_password': 'strongpassword'
        })
        self.assertEqual(response.status_code, 200)  
        self.assertTrue(User.objects.filter(email='test@example.com').exists())
        self.assertEqual(len(mail.outbox), 2)  

    def test_duplicate_email(self):
        User.objects.create_user('existing@example.com', 'existing@example.com', 'password')
        response = self.client.post(reverse('signup'), {
            'email': 'existing@example.com',
            'first_name': 'Jane',
            'last_name': 'Doe',
            'password': 'strongpassword',
            'confirm_password': 'strongpassword'
        })
        self.assertEqual(response.status_code, 302)  
        messages = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertIn("Email Already Registered!!", messages)
        self.assertFalse(User.objects.filter(first_name='Jane').exists())

    def test_password_mismatch(self):
        response = self.client.post(reverse('signup'), {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'strongpassword',
            'confirm_password': 'differentpassword'
        })
        self.assertEqual(response.status_code, 302) 
        messages = [str(message) for message in get_messages(response.wsgi_request)]
        self.assertIn("Passwords didn't matched!!", messages)
        self.assertFalse(User.objects.filter(email='test@example.com').exists())

class ContactUsViewTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.contact_us_url = reverse('contact_us')

    def test_contact_us_post(self):
        post_data = {
            'email': 'test@example.com',
            'message': 'This is a test message.'
        }
        response = self.client.post(self.contact_us_url, post_data)
        self.assertEqual(response.status_code, 302)  
        self.assertRedirects(response, reverse('home'))
        self.assertEqual(len(mail.outbox), 1)  
        self.assertEqual(mail.outbox[0].subject, 'Query for NextGen Retail Website')
        self.assertIn('Email: test@example.com', mail.outbox[0].body)
        self.assertIn('Message: This is a test message.', mail.outbox[0].body)

    def test_contact_us_get(self):
        response = self.client.get(self.contact_us_url)
        self.assertEqual(response.status_code, 200)  
        self.assertTemplateUsed(response, 'authentication/index.html')

class SignOutViewTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.signout_url = reverse('signout')
        self.home_url = reverse('home')  

    def test_signout_authenticated_user(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

        response = self.client.get(self.signout_url)

        self.assertEqual(response.status_code, 302)  
        self.assertRedirects(response, self.home_url)  
        self.assertFalse('_auth_user_id' in self.client.session)  

    def test_signout_message(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        self.client.login(username='testuser', password='testpassword')
        response = self.client.get(self.signout_url, follow=True)
        messages = list(response.context.get('messages', []))
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), "Logged out successfully!")

    def tearDown(self):
        User.objects.all().delete()     

class ChangePasswordViewTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.change_password_url = reverse('change_password')
        self.signin_url = reverse('signin')          
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    def test_change_password_valid(self):
        data = {
            'old_password': 'testpassword',
            'new_password': 'newpassword',
            'confirm_new_password': 'newpassword'
        }
        response = self.client.post(self.change_password_url, data)
        self.assertRedirects(response, self.signin_url)  
        self.assertTrue(User.objects.get(username='testuser').check_password('newpassword'))  

    def test_change_password_incorrect_old_password(self):
        data = {
            'old_password': 'incorrectpassword',
            'new_password': 'newpassword',
            'confirm_new_password': 'newpassword'
        }
        response = self.client.post(self.change_password_url, data, follow=True)

        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), 'Incorrect old password. Please try again.')

    def test_change_password_mismatched_new_passwords(self):
        data = {
            'old_password': 'testpassword',
            'new_password': 'newpassword1',
            'confirm_new_password': 'newpassword2'
        }
        response = self.client.post(self.change_password_url, data, follow=True)

        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), 'New passwords do not match. Please try again.')

    def test_change_password_get_request(self):
        response = self.client.get(self.change_password_url)
        self.assertEqual(response.status_code, 200)  

    def tearDown(self):
        User.objects.all().delete()

class DeleteUserViewTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.delete_user_url = reverse('delete_user')
        self.home_url = reverse('home')  

        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        self.client.login(username='testuser', password='testpassword')

    def test_delete_user_confirm_yes(self):
        data = {'confirm': 'yes'}
        response = self.client.post(self.delete_user_url, data, follow=True)
        self.assertFalse(User.objects.filter(username='testuser').exists())
        self.assertRedirects(response, self.home_url)
        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        self.assertEqual(str(messages[0]), 'Your account has been deleted successfully!')

    def test_delete_user_confirm_no(self):
        data = {'confirm': 'no'}
        response = self.client.post(self.delete_user_url, data, follow=True)
        self.assertTrue(User.objects.filter(username='testuser').exists())
        self.assertRedirects(response, reverse('predict'))

    def test_delete_user_get_request(self):
        response = self.client.get(self.delete_user_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'authentication/delete_user_confirmation.html')

class SignInViewTestCase(TestCase):

    def setUp(self):
        self.client = Client()
        self.signin_url = reverse('signin')
        self.user = User.objects.create_user(username='test@example.com', email='test@example.com', password='testpassword')

    def test_signin_valid_credentials(self):
        response = self.client.post(self.signin_url, {'email': 'test@example.com', 'password': 'testpassword'})
        self.assertEqual(response.status_code, 302)  
        self.assertRedirects(response, reverse('predict'))

 
    def test_signin_redirect(self):
        response = self.client.post(self.signin_url, {'email': 'test@example.com', 'password': 'password'})
        self.assertRedirects(response, reverse('signin'))
        self.assertEqual(response.status_code, 302)


    def test_signin_invalid_credentials(self):
        response = self.client.post(self.signin_url, {'email': 'test@example.com', 'password': 'wrongpassword'})
        self.assertRedirects(response, reverse('signin'))
        self.assertEqual(response.status_code, 302)  
        
    def test_signin_get_request(self):
        response = self.client.get(self.signin_url)
        self.assertEqual(response.status_code, 200)  
        self.assertTemplateUsed(response, 'authentication/signin.html')

