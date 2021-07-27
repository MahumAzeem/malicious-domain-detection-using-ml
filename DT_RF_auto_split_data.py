#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics 


# In[2]:


#Creates the columns for each of the features in csv data
columns = ['url','malicious','url_res','hostname_res','path_res',
           'first_dir_res','top_level_res','dash_res','at_res','q_res',
           'percent_res','dot_res','equal_res','colon_res','www_res','numbers_res','letters_res',
           'dir_res','single_letter_res','query_res','ratio_upper_lower_res','ip_res','shortened_res','http_res']

#Reads them into results from shuffled output file
results = pandas.read_csv('../data/kaggle_out.csv', header=None, names=columns)


# In[44]:


results = results.drop([results.index[0]]) #this is to delete row with headers
#results = results.drop([results.index[4132]]) #this is to delete row with headers after combining files

#Parses data into numerical values to be used to train and test data
droppedResults = results.drop(columns=['malicious', 'url'])
droppedResults['url_res'] = pandas.to_numeric(droppedResults['url_res'], downcast='integer')
droppedResults['hostname_res'] = pandas.to_numeric(droppedResults['hostname_res'])
droppedResults['path_res'] = pandas.to_numeric(droppedResults['path_res'])
droppedResults['first_dir_res'] = pandas.to_numeric(droppedResults['first_dir_res'])
droppedResults['top_level_res'] = pandas.to_numeric(droppedResults['top_level_res'])
droppedResults['dash_res'] = pandas.to_numeric(droppedResults['dash_res'])
droppedResults['at_res'] = pandas.to_numeric(droppedResults['at_res'])
droppedResults['q_res'] = pandas.to_numeric(droppedResults['q_res'])
droppedResults['percent_res'] = pandas.to_numeric(droppedResults['percent_res'])
droppedResults['dot_res'] = pandas.to_numeric(droppedResults['dot_res'])
droppedResults['equal_res'] = pandas.to_numeric(droppedResults['equal_res'])
droppedResults['colon_res'] = pandas.to_numeric(droppedResults['colon_res'])
droppedResults['www_res'] = pandas.to_numeric(droppedResults['www_res'])
droppedResults['numbers_res'] = pandas.to_numeric(droppedResults['numbers_res'])
droppedResults['letters_res'] = pandas.to_numeric(droppedResults['letters_res'])
droppedResults['dir_res'] = pandas.to_numeric(droppedResults['dir_res'])
droppedResults['single_letter_res'] = pandas.to_numeric(droppedResults['single_letter_res'])
droppedResults['query_res'] = pandas.to_numeric(droppedResults['query_res'])
droppedResults['ratio_upper_lower_res'] = pandas.to_numeric(droppedResults['ratio_upper_lower_res'])
droppedResults['ip_res'] = pandas.to_numeric(droppedResults['ip_res'])
droppedResults['shortened_res'] = pandas.to_numeric(droppedResults['shortened_res'])
droppedResults['http_res'] = pandas.to_numeric(droppedResults['http_res'])

#Sets x to the features without the URL or malicious attributes included
x = droppedResults.values

results['malicious'] = pandas.to_numeric(results['malicious'])

#Sets y to the boolean value of if URL was malicious or not
y = results['malicious'].values

print(x)
print(y)

print(x.shape)
print(y.shape)


# In[45]:


#Splits data into train and test data sets based on test size. 
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.3, random_state = 1)


# In[46]:


#Creates a decision tree classifier
tree = DecisionTreeClassifier()

#Fits the tree to the training data
tree.fit(x_train, y_train)

#Makes a prediction on training data
pred_train = tree.predict(x_train)
print(pred_train)

#Makes a predicition on test data
pred_test = tree.predict(x_test)
print(pred_test)


# In[47]:


#Prints accuracy of training data based on true values (y values, if URL was malicious)
accuracy_train = metrics.accuracy_score(y_train, pred_train)
print(accuracy_train)


# In[48]:


#Prints accuracy of test data based on true values (y values, if URL was malicious)
accuracy_test = metrics.accuracy_score(y_test, pred_test)
print(accuracy_test)


# In[49]:


#Prints error value based on test data accuracy
error = 1 - accuracy_test
print(error)


# In[50]:


#Creates a random forest classifier
forest = RandomForestClassifier()

#Fits the random forest to the training data
forest.fit(x_train, y_train)

#Makes a prediction on training data
pred_train = forest.predict(x_train)
print(pred_train)

#Makes a prediction on test data
pred_test = forest.predict(x_test)
print(pred_test)


# In[51]:


#Prints accuracy of training data based on true values (y values, if URL was malicious)
accuracy_train = metrics.accuracy_score(y_train, pred_train)
print(accuracy_train)


# In[52]:


#Prints accuracy of test data based on true values (y values, if URL was malicious)
accuracy_test = metrics.accuracy_score(y_test, pred_test)
print(accuracy_test)


# In[53]:


#Prints error value based on test data accuracy
error = 1 - accuracy_test
print(error)


# In[ ]:




