/** ExampleCallout.c

Implementation of an example Callout that inspects
outbound TCP traffic at the FWPM_OUTBOUND_TRANSPORT_V4
layer. This callout's ClassifyFn function prints the packets
TCP 4-tuple, and blocks the packet if it is bound for remote
port 1234. This Callout's NotifyFn function prints a message.

Author: Romanenko
*/

#include "Callout.h"

#define FORMAT_ADDR(x) (x>>24)&0xFF, (x>>16)&0xFF, (x>>8)&0xFF, x&0xFF

struct filterList* first = NULL;
struct filterList* last = NULL;
BOOL filter_state = FALSE;

/*************************
	ClassifyFn Function
**************************/
void example_classify(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut)
{
	UINT32 local_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remote_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 local_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remote_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
	UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;

	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);

	int countRule = 0;

	struct filterList* aux = first;

	DbgPrint("Example Classify found a packet: %d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu protocol:%hhu",
		FORMAT_ADDR(local_address), local_port, FORMAT_ADDR(remote_address), remote_port, protocol);

	//otherwise, we compare the packet with our rules
	while (aux != NULL && filter_state)
	{
		DbgPrint("Comparing with Rule %d", countRule);

		//if protocol is the same
		if (aux->ipf.protocol == 0 || protocol == aux->ipf.protocol)
		{
			//we look in source Address
			if (aux->ipf.sourceIp != 0 && remote_address != aux->ipf.sourceIp)
			{
				aux = aux->next;
				countRule++;
				continue;
			}

			//we look in destination address
			if (aux->ipf.destinationIp != 0 &&
				(local_address != aux->ipf.destinationIp))
			{
				aux = aux->next;
				countRule++;
				continue;
			}

			
			if (aux->ipf.sourcePort == 0 || remote_port == aux->ipf.sourcePort)
			{
				if (aux->ipf.destinationPort == 0 ||
					local_port == aux->ipf.destinationPort)
				{
					//decide what to do with the packet
					if (aux->ipf.drop)
					{
						classifyOut->actionType = FWP_ACTION_BLOCK;
						return;
					}
					else
					{
						classifyOut->actionType = FWP_ACTION_PERMIT;
						return;
					}
				}
			}
		}

		else
		{
			//for other packet we dont look more 
			//decide what to do with the packet
			if (aux->ipf.drop)
			{
				classifyOut->actionType = FWP_ACTION_BLOCK;
				return;
			}
			else
			{
				classifyOut->actionType = FWP_ACTION_PERMIT;
				return;
			}
		}

		//compare with the next rule
		countRule++;
		aux = aux->next;
	}

	//we accept all not registered
	classifyOut->actionType = FWP_ACTION_PERMIT;
	return;
}

/*************************
	NotifyFn Function
**************************/
NTSTATUS example_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID* filterKey,
	const FWPS_FILTER* filter)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	switch (notifyType) {
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		DbgPrint("A new filter has registered Example Callout as its action");
		break;
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		DbgPrint("A filter that uses Example Callout has just been deleted");
		break;
	}
	return status;
}

/***************************
	FlowDeleteFn Function
****************************/
NTSTATUS example_flow_delete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
	return STATUS_SUCCESS;
}

NTSTATUS AddFilterToList(IPFilter* pf)
{
	DbgPrint("Rule: %d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu protocol:%hhu",
		FORMAT_ADDR(pf->sourceIp), pf->sourcePort, FORMAT_ADDR(pf->destinationIp), pf->destinationPort, pf->protocol);

	struct filterList* aux = NULL;

	//reserve memory to the new filter
	aux = (struct filterList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct filterList), '1gaT');

	if (aux == NULL)
	{
		DbgPrint("Problem reserving memory\n");

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//fill the new structure
	aux->ipf.destinationIp = pf->destinationIp;
	aux->ipf.sourceIp = pf->sourceIp;

	aux->ipf.destinationPort = pf->destinationPort;
	aux->ipf.sourcePort = pf->sourcePort;

	aux->ipf.protocol = pf->protocol;

	aux->ipf.drop = pf->drop;

	//Add the new filter to the filter list
	if (first == NULL)
	{
		first = last = aux;

		first->next = NULL;
	}

	else
	{
		last->next = aux;
		last = aux;
		last->next = NULL;
	}

	return STATUS_SUCCESS;
}

void ClearFilterList(void)
{
	struct filterList* aux = NULL;

	//free the linked list
	DbgPrint("Removing the filter List...");

	while (first != NULL)
	{
		aux = first;
		first = first->next;
		ExFreePool(aux);

		DbgPrint("One Rule removed");
	}

	first = last = NULL;

	DbgPrint("Removed is complete.");
}

void Start(BOOL start) 
{
	filter_state = start;
}