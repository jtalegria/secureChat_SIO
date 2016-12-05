package client;

import java.io.OutputStream;
import com.google.gson.*;

public class ClientDescription implements Comparable {

public String id; // id extracted from the JASON description
public JsonElement description; // JSON description of the client, including id
public OutputStream out;	 // Stream to send messages to the client

public ClientDescription ( String id, JsonElement description, OutputStream out )
{
    this.id = id;
    this.description = description;
    this.out = out;
}

public int
compareTo ( Object x )
{
    return ((ClientDescription) x).id.compareTo ( id );
}

}