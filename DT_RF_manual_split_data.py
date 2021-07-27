#!/usr/bin/env python
# coding: utf-8

# In[43]:


import pandas
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics 
from sklearn import tree

import matplotlib
import matplotlib.pyplot as plt
#import graphviz


# In[44]:


#Creates the columns for each of the features in csv data
columns = ['url','malicious','url_res','hostname_res','path_res',
           'first_dir_res','top_level_res','dash_res','at_res','q_res',
           'percent_res','dot_res','equal_res','colon_res','www_res','numbers_res','letters_res',
           'dir_res','single_letter_res','query_res','ratio_upper_lower_res','ip_res','shortened_res','http_res']

#Reads training data into resultsTrain from shuffled output file containing training data
resultsTrain = pandas.read_csv('../data/kaggle_out.csv', header=None, names=columns)


# In[45]:


#Reads test data into resultsTest from shuffled output file containing test data
resultsTest = pandas.read_csv('../data/output_shuff_70.csv', header=None, names=columns)


# In[46]:


resultsTrain = resultsTrain.drop([resultsTrain.index[0]]) #this is to delete row with headers

#Parses data into numerical values to be used to training data
droppedResults = resultsTrain.drop(columns=['malicious', 'url'])
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

#Sets x_train to the features without the URL or malicious attributes included from training data
x_train = droppedResults.values

resultsTrain['malicious'] = pandas.to_numeric(resultsTrain['malicious'])

#Sets y_train to the boolean value of if URL was malicious or not
y_train = resultsTrain['malicious'].values

print(x_train)
print(y_train)

print(x_train.shape)
print(y_train.shape)


# In[47]:


resultsTest = resultsTest.drop([resultsTest.index[0]]) #this is to delete row with headers

#Parses data into numerical values to be used to test data
droppedResults = resultsTest.drop(columns=['malicious', 'url'])

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

#Sets x_test to the features without the URL or malicious attributes included from training data
x_test = droppedResults.values

resultsTest['malicious'] = pandas.to_numeric(resultsTest['malicious'])

#Sets y_test to the boolean value of if URL was malicious or not
y_test = resultsTest['malicious'].values

print(x_test)
print(y_test)

print(x_test.shape)
print(y_test.shape)


# In[48]:


#Creates a decision tree classifier
dtree = DecisionTreeClassifier(max_depth=7, max_features="auto")

#Fits the tree to the training data
fitted = dtree.fit(x_train, y_train)

#Makes a prediction on training data
pred_train = dtree.predict(x_train)
print(pred_train)

#Makes a predicition on test data
pred_test = dtree.predict(x_test)
print(pred_test)


# In[49]:


#Creates a plot of decision tree
#plt.figure(figsize=(12,12))
#tree.plot_tree(fitted, fontsize=10)
#plt.show()


# In[50]:


#Prints accuracy of training data based on true values (y_train values, if URL was malicious)
accuracy_train = metrics.accuracy_score(y_train, pred_train)
print(accuracy_train)


# In[51]:


#Prints accuracy of training data based on true values (y_test values, if URL was malicious)
accuracy_test = metrics.accuracy_score(y_test, pred_test)
print(accuracy_test)


# In[52]:


#Prints error value based on test data accuracy
error = 1 - accuracy_test
print(error)


# In[53]:


#Creates a random forest classifier
forest = RandomForestClassifier(n_estimators=70, max_depth=6, max_features="auto", max_leaf_nodes=30)

#Fits the random forest to the training data
forest.fit(x_train, y_train)

#Makes a prediction on training data
pred_train = forest.predict(x_train)
print(pred_train)

#Makes a prediction on test data
pred_test = forest.predict(x_test)
print(pred_test)


# In[54]:


#Prints accuracy of training data based on true values (y_train values, if URL was malicious)
accuracy_train = metrics.accuracy_score(y_train, pred_train)
print(accuracy_train)


# In[55]:


#Prints accuracy of training data based on true values (y_test values, if URL was malicious)
accuracy_test = metrics.accuracy_score(y_test, pred_test)
print(accuracy_test)


# In[56]:


#Prints error value based on test data accuracy
error = 1 - accuracy_test
print(error)


# In[ ]:




